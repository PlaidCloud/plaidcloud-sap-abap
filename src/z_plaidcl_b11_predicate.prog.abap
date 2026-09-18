REPORT z_plaidcl_b11_predicate.
*----------------------------------------------------------------------
* sc-27809 (B11 predicate safety), sc-28907 (select-option semantics).
* Structured filter spec -> validated SQL fragment(s), split across
* multiple RFC_READ_TABLE OPTIONS rows so no single row's TEXT field
* (typed C(72), see RFC_DB_OPT) is ever handed a fragment longer than
* it can hold. A naive single-row OPTIONS-TEXT silently truncates at
* 72 characters -- compiler warning only if the source is a literal,
* nothing at all if it is a runtime MOVE -- and the truncated WHERE
* clause can still be syntactically valid, just wrong. This program
* proves both truncation paths and proves the splitter avoids them.
*
* Predicates use SAP select-option semantics, the same grammar as
* Z_PLAIDCL_B5_READ_TABLE's IT_PREDICATES (lcl_b5_predicate):
*   SIGN I/E, OP EQ NE GT GE LT LE BT NB CP NP, HIGH only for BT/NB. Per
*   field: (I1 OR I2 ...) AND NOT E1 ...; fields ANDed. A row without SIGN
*   is a legacy row: rendered as I, ANDed as its own term, as B5 does.
*   An E row renders as the complementary option. CP/NP: * -> %, + -> _,
*   SAP's #x is a literal x, a literal % _ # is escaped (ESCAPE '#').
*----------------------------------------------------------------------

START-OF-SELECTION.
  " no-op interactively; ltcl_b11 drives every check.

*----------------------------------------------------------------------
* Deliberate reproduction of the ACTIVATION-time silent truncation:
* this literal is 89 characters; DD03L-ROLLNAME-style C(72) targets
* cannot hold it. SAP's syntax check truncates it to the first 72
* characters with a WARNING only (code MESSAGE(GTW)) -- activation
* still succeeds. gv_oversized_literal's RUNTIME value is proof: it
* holds only the first 72 characters the source literal below, even
* though the source clearly specifies more.
*----------------------------------------------------------------------
DATA gv_oversized_literal TYPE c LENGTH 72 VALUE
  'AAAAAAAAAA1AAAAAAAAAA2AAAAAAAAAA3AAAAAAAAAA4AAAAAAAAAA5AAAAAAAAAA6AAAAAAAAAA7AAAAAAAAAA8AAAAAAAAAA9'.

*----------------------------------------------------------------------
* Structured predicate spec. There is NO variant of this API that
* accepts a raw WHERE string -- the type system is the first control.
* reject_raw_passthrough exists only so the refusal is independently
* testable, not as the actual gate (the gate is "there is no such
* parameter").
*----------------------------------------------------------------------
TYPES: BEGIN OF ty_predicate,
         fieldname TYPE string,
         sign      TYPE string,   " I E (initial = legacy AND term)
         op        TYPE string,   " EQ NE GT GE LT LE BT NB CP NP
         value     TYPE string,
         high      TYPE string,   " BT NB only
       END OF ty_predicate,
       ty_predicates TYPE STANDARD TABLE OF ty_predicate WITH EMPTY KEY,
       ty_options    TYPE STANDARD TABLE OF rfc_db_opt WITH DEFAULT KEY.

CLASS lcx_predicate DEFINITION INHERITING FROM cx_static_check FINAL.
  PUBLIC SECTION.
    DATA msg TYPE string READ-ONLY.
    METHODS constructor IMPORTING msg TYPE string.
ENDCLASS.

CLASS lcx_predicate IMPLEMENTATION.
  METHOD constructor.
    super->constructor( ).
    me->msg = msg.
  ENDMETHOD.
ENDCLASS.

CLASS lcl_predicate_builder DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_max_row_len TYPE i VALUE 72.
    " Reserve 1 char per row for the safety-joining trailing space we
    " insert between rows (SAP concatenates OPTIONS rows verbatim, no
    " separator of its own) -- so packed content may use at most 71.
    CONSTANTS c_pack_budget TYPE i VALUE 71.

    CLASS-METHODS render_condition
      IMPORTING ps_pred        TYPE ty_predicate
      RETURNING VALUE(rv_text) TYPE string
      RAISING   lcx_predicate.

    CLASS-METHODS build_predicate_text
      IMPORTING pt_preds       TYPE ty_predicates
      RETURNING VALUE(rv_text) TYPE string
      RAISING   lcx_predicate.

    " The ONLY way to get a WHERE fragment onto the wire: structured
    " spec in, safely-split RFC_DB_OPT rows out. No raw-string overload
    " exists alongside this method.
    CLASS-METHODS predicate_to_options
      IMPORTING pt_preds          TYPE ty_predicates
      RETURNING VALUE(rt_options) TYPE ty_options
      RAISING   lcx_predicate.

    " Token-safe splitter usable directly on an already-built string,
    " so it can be unit-tested independently of predicate rendering.
    CLASS-METHODS split_to_options
      IMPORTING pv_text           TYPE string
      RETURNING VALUE(rt_options) TYPE ty_options
      RAISING   lcx_predicate.

    " Exists purely to prove the refusal is real and independently
    " testable: this is what "no raw passthrough" looks like when
    " someone tries anyway.
    CLASS-METHODS reject_raw_passthrough
      IMPORTING pv_raw_where TYPE string
      RAISING   lcx_predicate.

    " debug-only exposure of the tokenizer, for direct inspection.
    CLASS-METHODS debug_tokenize
      IMPORTING pv_text          TYPE string
      RETURNING VALUE(rt_tokens) TYPE string_table.

  PRIVATE SECTION.
    CLASS-METHODS escape_literal
      IMPORTING pv_value       TYPE string
      RETURNING VALUE(rv_esc)  TYPE string.

    CLASS-METHODS like_pattern
      IMPORTING pv_value          TYPE string
      RETURNING VALUE(rv_pattern) TYPE string.

    " Quoted literal; an empty value is ' ', never '' (as B5's literal).
    CLASS-METHODS literal
      IMPORTING pv_value      TYPE string
      RETURNING VALUE(rv_sql) TYPE string.

    CLASS-METHODS tokenize
      IMPORTING pv_text          TYPE string
      RETURNING VALUE(rt_tokens) TYPE string_table.
ENDCLASS.

CLASS lcl_predicate_builder IMPLEMENTATION.

  METHOD escape_literal.
    " Double any embedded single quotes so a literal can never break
    " out of its own quoting.
    rv_esc = pv_value.
    REPLACE ALL OCCURRENCES OF `'` IN rv_esc WITH `''`.
  ENDMETHOD.

  METHOD literal.
    rv_sql = COND #( WHEN pv_value IS INITIAL THEN `' '` ELSE |'{ escape_literal( pv_value ) }'| ).
  ENDMETHOD.

  METHOD like_pattern.
    DATA lv_pos TYPE i.
    DATA(lv_len) = strlen( pv_value ).
    WHILE lv_pos < lv_len.
      DATA(lv_char) = substring( val = pv_value off = lv_pos len = 1 ).
      lv_pos = lv_pos + 1.
      IF lv_char = `#` AND lv_pos < lv_len.
        lv_char = substring( val = pv_value off = lv_pos len = 1 ).
        lv_pos = lv_pos + 1.
        rv_pattern = rv_pattern && COND string( WHEN lv_char = `%` OR lv_char = `_` OR lv_char = `#`
                                                THEN |#{ lv_char }| ELSE lv_char ).
        CONTINUE.
      ENDIF.
      rv_pattern = rv_pattern && SWITCH string( lv_char
        WHEN `*` THEN `%`
        WHEN `+` THEN `_`
        WHEN `%` THEN `#%`
        WHEN `_` THEN `#_`
        WHEN `#` THEN `##`
        ELSE lv_char ).
    ENDWHILE.
  ENDMETHOD.

  METHOD render_condition.
    " Validated SQL: fieldname must look like an ABAP DDIC field name.
    " Anything else (spaces, quotes, parens, SQL keywords smuggled in
    " as a "fieldname") is rejected outright -- this is the actual
    " injection control, independent of the 72-char splitter below.
    " \z, not $: POSIX $ also matches before a newline (B5 check_identifier).
    FIND PCRE '^[A-Z][A-Z0-9_]{0,29}\z' IN ps_pred-fieldname IGNORING CASE.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE lcx_predicate
        EXPORTING msg = |Rejected fieldname [{ ps_pred-fieldname }]: not a valid identifier|.
    ENDIF.

    DATA(lv_sign) = COND string( WHEN ps_pred-sign IS INITIAL THEN `I` ELSE to_upper( ps_pred-sign ) ).
    DATA(lv_given) = to_upper( ps_pred-op ).
    IF lv_sign <> `I` AND lv_sign <> `E`.
      RAISE EXCEPTION TYPE lcx_predicate
        EXPORTING msg = |Rejected sign [{ ps_pred-sign }]: not I or E|.
    ENDIF.
    IF NOT matches( val = lv_given regex = `EQ|NE|GT|GE|LT|LE|BT|NB|CP|NP` ).
      RAISE EXCEPTION TYPE lcx_predicate
        EXPORTING msg = |Rejected operator [{ ps_pred-op }]: not in the allowed set|.
    ENDIF.
    DATA(lv_ranged) = xsdbool( lv_given = `BT` OR lv_given = `NB` ).
    IF lv_ranged <> xsdbool( ps_pred-high IS NOT INITIAL ).
      RAISE EXCEPTION TYPE lcx_predicate
        EXPORTING msg = |Rejected operator [{ ps_pred-op }]: HIGH is required for BT/NB and refused otherwise|.
    ENDIF.

    DATA(lv_op) = COND string(
      WHEN lv_sign = `I` THEN lv_given
      ELSE SWITCH string( lv_given
             WHEN `EQ` THEN `NE`  WHEN `NE` THEN `EQ`
             WHEN `GT` THEN `LE`  WHEN `GE` THEN `LT`
             WHEN `LT` THEN `GE`  WHEN `LE` THEN `GT`
             WHEN `BT` THEN `NB`  WHEN `NB` THEN `BT`
             WHEN `CP` THEN `NP`  ELSE `CP` ) ).
    DATA(lv_field) = to_upper( ps_pred-fieldname ).
    DATA(lv_low)   = literal( ps_pred-value ).
    DATA(lv_high)  = literal( ps_pred-high ).
    DATA(lv_like)  = literal( like_pattern( ps_pred-value ) ).

    rv_text = SWITCH #( lv_op
      WHEN `EQ` THEN |{ lv_field } = { lv_low }|
      WHEN `NE` THEN |{ lv_field } <> { lv_low }|
      WHEN `GT` THEN |{ lv_field } > { lv_low }|
      WHEN `GE` THEN |{ lv_field } >= { lv_low }|
      WHEN `LT` THEN |{ lv_field } < { lv_low }|
      WHEN `LE` THEN |{ lv_field } <= { lv_low }|
      WHEN `BT` THEN |{ lv_field } BETWEEN { lv_low } AND { lv_high }|
      WHEN `NB` THEN |{ lv_field } NOT BETWEEN { lv_low } AND { lv_high }|
      WHEN `CP` THEN |{ lv_field } LIKE { lv_like } ESCAPE '#'|
      ELSE           |{ lv_field } NOT LIKE { lv_like } ESCAPE '#'| ).
  ENDMETHOD.

  METHOD build_predicate_text.
    DATA lt_fields   TYPE string_table.
    DATA lv_include  TYPE string.
    DATA lv_exclude  TYPE string.
    DATA lv_includes TYPE i.
    DATA lv_cond     TYPE string.
    DATA lv_part     TYPE string.

    LOOP AT pt_preds INTO DATA(ls_pred).
      DATA(lv_name) = to_upper( ls_pred-fieldname ).
      IF ls_pred-sign IS INITIAL.
        " No SIGN: a legacy row, its own AND term (B5 to_where).
        lv_cond = render_condition( ls_pred ).
        rv_text = COND #( WHEN rv_text IS INITIAL THEN lv_cond ELSE |{ rv_text } AND { lv_cond }| ).
      ELSEIF NOT line_exists( lt_fields[ table_line = lv_name ] ).
        APPEND lv_name TO lt_fields.
      ENDIF.
    ENDLOOP.

    LOOP AT lt_fields INTO DATA(lv_field).
      CLEAR: lv_include, lv_exclude, lv_includes.
      LOOP AT pt_preds INTO ls_pred.
        IF to_upper( ls_pred-fieldname ) <> lv_field OR ls_pred-sign IS INITIAL.
          CONTINUE.
        ENDIF.
        lv_cond = render_condition( ls_pred ).
        IF to_upper( ls_pred-sign ) = `I`.
          lv_includes = lv_includes + 1.
          lv_include = COND #( WHEN lv_include IS INITIAL THEN lv_cond ELSE |{ lv_include } OR { lv_cond }| ).
        ELSE.
          lv_exclude = COND #( WHEN lv_exclude IS INITIAL THEN lv_cond ELSE |{ lv_exclude } AND { lv_cond }| ).
        ENDIF.
      ENDLOOP.
      IF lv_includes > 1.
        lv_include = |( { lv_include } )|.
      ENDIF.
      lv_part = COND #( WHEN lv_include IS INITIAL THEN lv_exclude
                        WHEN lv_exclude IS INITIAL THEN lv_include
                        ELSE |{ lv_include } AND { lv_exclude }| ).
      rv_text = COND #( WHEN rv_text IS INITIAL THEN lv_part ELSE |{ rv_text } AND { lv_part }| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD reject_raw_passthrough.
    RAISE EXCEPTION TYPE lcx_predicate
      EXPORTING msg = |Raw WHERE passthrough is forbidden. Received { strlen( pv_raw_where ) } | &&
                      |raw chars; structured predicates only.|.
  ENDMETHOD.

  METHOD tokenize.
    " Split pv_text on spaces that are NOT inside a single-quoted
    " literal, so a break can never land mid-identifier or mid-literal.
    " Strategy: find every complete '...'-literal (an embedded quote is
    " escaped as '' per escape_literal), replace ONLY the spaces INSIDE
    " each such literal with a sentinel byte, split the whole string on
    " plain spaces (now safe -- every remaining space is a real
    " token boundary), then restore the sentinel back to a space
    " inside each token.
    CONSTANTS lc_sentinel TYPE c LENGTH 1 VALUE cl_abap_char_utilities=>minchar.

    DATA(lv_protected) = pv_text.
    DATA(lv_off) = 0.
    DO.
      FIND REGEX `'([^']|'')*'` IN SECTION OFFSET lv_off OF lv_protected
        MATCH OFFSET DATA(lv_moff) MATCH LENGTH DATA(lv_mlen).
      IF sy-subrc <> 0.
        EXIT.
      ENDIF.
      DATA(lv_match) = lv_protected+lv_moff(lv_mlen).
      REPLACE ALL OCCURRENCES OF ` ` IN lv_match WITH lc_sentinel.
      DATA(lv_rest_off) = lv_moff + lv_mlen.
      lv_protected = lv_protected(lv_moff) && lv_match && lv_protected+lv_rest_off.
      lv_off = lv_rest_off.
    ENDDO.

    SPLIT lv_protected AT ` ` INTO TABLE rt_tokens.
    DELETE rt_tokens WHERE table_line IS INITIAL.
    LOOP AT rt_tokens ASSIGNING FIELD-SYMBOL(<lv_tok>).
      REPLACE ALL OCCURRENCES OF lc_sentinel IN <lv_tok> WITH ` `.
    ENDLOOP.
  ENDMETHOD.

  METHOD split_to_options.
    DATA(lt_tokens) = tokenize( pv_text ).
    DATA lv_line TYPE string VALUE ``.

    LOOP AT lt_tokens INTO DATA(lv_token).
      IF strlen( lv_token ) > c_pack_budget.
        RAISE EXCEPTION TYPE lcx_predicate
          EXPORTING msg = |Predicate token [{ lv_token }] is { strlen( lv_token ) } chars, | &&
                          |exceeds the { c_pack_budget }-char per-row budget (C(72) field, | &&
                          |1 char reserved for the inter-row separator) and cannot be safely split.|.
      ENDIF.

      DATA(lv_candidate) = COND string( WHEN lv_line IS INITIAL THEN lv_token
                                         ELSE |{ lv_line } { lv_token }| ).
      IF strlen( lv_candidate ) <= c_pack_budget.
        lv_line = lv_candidate.
      ELSE.
        APPEND VALUE #( text = lv_line && ` ` ) TO rt_options.
        lv_line = lv_token.
      ENDIF.
    ENDLOOP.
    IF lv_line IS NOT INITIAL.
      APPEND VALUE #( text = lv_line ) TO rt_options.
    ENDIF.

    LOOP AT rt_options INTO DATA(ls_check).
      IF strlen( ls_check-text ) > c_max_row_len.
        RAISE EXCEPTION TYPE lcx_predicate
          EXPORTING msg = |INTERNAL: packed row [{ ls_check-text }] is { strlen( ls_check-text ) } | &&
                          |chars, exceeds the hard { c_max_row_len }-char RFC_DB_OPT-TEXT bound.|.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD debug_tokenize.
    rt_tokens = tokenize( pv_text ).
  ENDMETHOD.

  METHOD predicate_to_options.
    DATA(lv_text) = build_predicate_text( pt_preds ).
    rt_options = split_to_options( lv_text ).
  ENDMETHOD.

ENDCLASS.

*----------------------------------------------------------------------
* Local test class: drives every probe. Every method asserts.
*----------------------------------------------------------------------
CLASS ltcl_b11 DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS:
      a_literal_truncation FOR TESTING,
      b_reject_bad_fieldname FOR TESTING,
      c_reject_bad_operator FOR TESTING,
      d_escapes_embedded_quote FOR TESTING RAISING lcx_predicate,
      e_raw_passthrough_forbidden FOR TESTING,
      f_splitter_keeps_tokens_intact FOR TESTING RAISING lcx_predicate,
      g_splitter_asserts_oversize FOR TESTING,
      h_truncation_vs_split_dd03l FOR TESTING,
      i_select_options_render FOR TESTING RAISING lcx_predicate,
      j_select_options_dd03l FOR TESTING.
ENDCLASS.

CLASS ltcl_b11 IMPLEMENTATION.

  METHOD a_literal_truncation.
    DATA(lv_intended) =
      `AAAAAAAAAA1AAAAAAAAAA2AAAAAAAAAA3AAAAAAAAAA4AAAAAAAAAA5AAAAAAAAAA6AAAAAAAAAA7AAAAAAAAAA8AAAAAAAAAA9`.
    DATA(lv_msg) =
      |intended-source-literal-len={ strlen( lv_intended ) } | &&
      |runtime-value-of-gv_oversized_literal=[{ gv_oversized_literal }] | &&
      |runtime-len={ strlen( gv_oversized_literal ) }|.
    cl_abap_unit_assert=>assert_equals( act = strlen( gv_oversized_literal ) exp = 72
      msg = |A: a C(72) field can hold at most 72 chars: { lv_msg }| ).
    cl_abap_unit_assert=>assert_equals( act = gv_oversized_literal exp = substring( val = lv_intended len = 72 )
      msg = |A: the runtime value must be the first 72 chars of the intended literal: { lv_msg }| ).
  ENDMETHOD.

  METHOD b_reject_bad_fieldname.
    DATA(lt_names) = VALUE string_table( ( `TABNAME = 'X'; DROP` ) ( |TABNAME\n| ) ( |TAB\nNAME| ) ).
    LOOP AT lt_names INTO DATA(lv_name).
      DATA(lv_rejected) = abap_false.
      TRY.
          lcl_predicate_builder=>render_condition( VALUE #( fieldname = lv_name op = 'EQ' value = 'x' ) ).
        CATCH lcx_predicate.
          lv_rejected = abap_true.
      ENDTRY.
      cl_abap_unit_assert=>assert_true( act = lv_rejected
        msg = |B: fieldname [{ escape( val = lv_name format = cl_abap_format=>e_string_tpl ) }] must be rejected| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD c_reject_bad_operator.
    DATA lt_bad TYPE ty_predicates.
    lt_bad = VALUE #( ( fieldname = 'TABNAME' op = 'DROP TABLE' value = 'x' )
                      ( fieldname = 'TABNAME' sign = 'X' op = 'EQ' value = 'x' )
                      ( fieldname = 'TABNAME' op = 'BT' value = 'x' )
                      ( fieldname = 'TABNAME' op = 'EQ' value = 'x' high = 'y' ) ).
    LOOP AT lt_bad INTO DATA(ls_bad).
      DATA(lv_rejected) = abap_false.
      TRY.
          lcl_predicate_builder=>render_condition( ls_bad ).
        CATCH lcx_predicate.
          lv_rejected = abap_true.
      ENDTRY.
      cl_abap_unit_assert=>assert_true( act = lv_rejected
        msg = |C: [{ ls_bad-sign }/{ ls_bad-op }/{ ls_bad-high }] must be rejected| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD d_escapes_embedded_quote.
    DATA(lv_text) = lcl_predicate_builder=>render_condition(
      VALUE #( fieldname = 'FIELDNAME' op = 'EQ' value = `O'BRIEN` ) ).
    cl_abap_unit_assert=>assert_equals( act = lv_text exp = `FIELDNAME = 'O''BRIEN'`
      msg = |D: an embedded quote must be doubled: rendered=[{ lv_text }]| ).
    lv_text = lcl_predicate_builder=>render_condition( VALUE #( fieldname = 'FIELDNAME' op = 'NE' value = `` ) ).
    cl_abap_unit_assert=>assert_equals( act = lv_text exp = `FIELDNAME <> ' '`
      msg = |D: an empty value renders ' ' as B5 does: rendered=[{ lv_text }]| ).
  ENDMETHOD.

  METHOD e_raw_passthrough_forbidden.
    DATA(lv_rejected) = abap_false.
    DATA lv_msg TYPE string.
    TRY.
        lcl_predicate_builder=>reject_raw_passthrough( `TABNAME = 'DD02L'` ).
      CATCH lcx_predicate INTO DATA(lx).
        lv_rejected = abap_true.
        lv_msg = |OK rejected: { lx->msg }|.
    ENDTRY.
    cl_abap_unit_assert=>assert_true( act = lv_rejected
      msg = |E: raw WHERE passthrough must be rejected: { lv_msg }| ).
  ENDMETHOD.

  METHOD f_splitter_keeps_tokens_intact.
    " A crafted predicate with a literal that CONTAINS a space, long
    " enough that the row boundary would fall inside it if the
    " splitter were naive about spaces.
    DATA(lv_text) =
      `DESCRIPTION = 'has a space' AND ` &&
      `NOTES = 'another value with spaces' AND ` &&
      `STATUS = 'A' AND ` &&
      `REGION = 'B' AND ` &&
      `CATEGORY = 'C' AND ` &&
      `PRIORITY = 'D'`.
    DATA(lt_dbg_tokens) = lcl_predicate_builder=>debug_tokenize( lv_text ).
    DATA(lv_tok_dump) = ``.
    LOOP AT lt_dbg_tokens INTO DATA(lv_tok).
      lv_tok_dump = lv_tok_dump && |<{ lv_tok }>|.
    ENDLOOP.
    DATA(lv_msg) = |token_count={ lines( lt_dbg_tokens ) } tokens={ lv_tok_dump }. |.

    DATA(lt_opts) = lcl_predicate_builder=>split_to_options( lv_text ).
    DATA(lv_rejoined) = ``.
    LOOP AT lt_opts INTO DATA(ls_opt).
      " RFC_READ_TABLE joins OPTIONS rows with the reserved separator blank,
      " which a C(72) field loses on concatenation.
      lv_rejoined = lv_rejoined && ls_opt-text && ` `.
    ENDLOOP.
    CONDENSE lv_rejoined.
    DATA(lv_expected) = lv_text.
    CONDENSE lv_expected.
    lv_msg = lv_msg && |rows={ lines( lt_opts ) } rejoined=[{ lv_rejoined }]. |.
    LOOP AT lt_opts INTO ls_opt.
      lv_msg = lv_msg && | ; row[{ sy-tabix }]=[{ ls_opt-text }] len={ strlen( ls_opt-text ) }|.
    ENDLOOP.

    cl_abap_unit_assert=>assert_equals( act = lv_rejoined exp = lv_expected
      msg = |F: rejoined split rows must match the original text (condensed): { lv_msg }| ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lv_rejoined CS `another value with spaces` )
      msg = |F: the multi-word literal must survive the split intact: { lv_msg }| ).
    LOOP AT lt_opts INTO ls_opt.
      cl_abap_unit_assert=>assert_true( act = xsdbool( strlen( ls_opt-text ) <= 72 )
        msg = |F: row[{ sy-tabix }]=[{ ls_opt-text }] must fit the C(72) OPTIONS-TEXT field: { lv_msg }| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD g_splitter_asserts_oversize.
    DATA(lv_huge_value) = repeat( val = 'A' occ = 80 ).
    DATA(lv_rejected) = abap_false.
    DATA lv_msg TYPE string.
    TRY.
        lcl_predicate_builder=>split_to_options( |FIELDNAME = '{ lv_huge_value }'| ).
      CATCH lcx_predicate INTO DATA(lx).
        lv_rejected = abap_true.
        lv_msg = |OK rejected: { lx->msg }|.
    ENDTRY.
    cl_abap_unit_assert=>assert_true( act = lv_rejected
      msg = |G: an 80-char unsplittable token must be rejected: { lv_msg }| ).
  ENDMETHOD.

  METHOD h_truncation_vs_split_dd03l.
    " Build: '<21 A's>' = '<21 A's>' AND TABNAME = 'DD02L' AND FIELDNAME = 'TABNAME'
    " The filler condition is always-true and redundant by construction
    " (pure padding), so it changes nothing about which rows SHOULD
    " match: the correct answer is exactly 1 row (the TABNAME field's
    " own DD03L entry). Total length is engineered to 97 chars so that
    " truncating at exactly 72 lands cleanly right after "...DD02L'"
    " plus the following space -- i.e. cuts off "AND FIELDNAME =
    " 'TABNAME'" WHOLESALE, leaving a syntactically valid but wrong
    " (too broad) WHERE clause. This is the failure mode: not a syntax
    " error, a SILENTLY WRONG result set.
    DATA(lv_filler) = |'{ repeat( val = 'A' occ = 21 ) }' = '{ repeat( val = 'A' occ = 21 ) }'|.
    DATA(lv_cond1)  = `TABNAME = 'DD02L'`.
    DATA(lv_cond2)  = `FIELDNAME = 'TABNAME'`.
    DATA(lv_full)   = |{ lv_filler } AND { lv_cond1 } AND { lv_cond2 }|.

    DATA(lv_msg) = |full_len={ strlen( lv_full ) } (expect 97) full=[{ lv_full }]. |.

    " --- (1) THE LANDMINE: naive single-row OPTIONS, runtime MOVE-truncation ---
    DATA ls_naive_opt TYPE rfc_db_opt.
    ls_naive_opt-text = lv_full.   " silent truncation to 72 chars, no warning at all (runtime MOVE)
    lv_msg = lv_msg && |naive_row=[{ ls_naive_opt-text }] naive_row_len={ strlen( ls_naive_opt-text ) }. |.

    DATA lt_naive_options TYPE STANDARD TABLE OF rfc_db_opt.
    APPEND ls_naive_opt TO lt_naive_options.

    DATA lt_fields TYPE STANDARD TABLE OF rfc_db_fld.
    APPEND VALUE #( fieldname = 'TABNAME' )   TO lt_fields.
    APPEND VALUE #( fieldname = 'FIELDNAME' ) TO lt_fields.

    DATA lt_data_naive TYPE STANDARD TABLE OF tab512.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD03L' delimiter = '|' rowcount = 200
      TABLES options = lt_naive_options fields = lt_fields data = lt_data_naive
      EXCEPTIONS OTHERS = 7.
    DATA(lv_naive_subrc) = sy-subrc.
    lv_msg = lv_msg && |naive_call_subrc={ lv_naive_subrc } naive_rowcount={ lines( lt_data_naive ) }. |.

    " --- (2) THE FIX: structured predicate -> validated, token-safe split ---
    DATA(lt_preds) = VALUE ty_predicates(
      ( fieldname = 'TABNAME'   op = 'EQ' value = 'DD02L' )
      ( fieldname = 'FIELDNAME' op = 'EQ' value = 'TABNAME' ) ).
    " (the filler is deliberately NOT part of the structured spec --
    " it exists purely to manufacture an over-length raw string for
    " the landmine side of this demo; the safe path never needs it.)

    DATA lt_data_safe TYPE STANDARD TABLE OF tab512.
    TRY.
        DATA(lt_safe_options) = lcl_predicate_builder=>predicate_to_options( lt_preds ).
        CALL FUNCTION 'RFC_READ_TABLE'
          EXPORTING query_table = 'DD03L' delimiter = '|' rowcount = 200
          TABLES options = lt_safe_options fields = lt_fields data = lt_data_safe
          EXCEPTIONS OTHERS = 7.
        DATA(lv_safe_subrc) = sy-subrc.
        lv_msg = lv_msg && |safe_call_subrc={ lv_safe_subrc } safe_rowcount={ lines( lt_data_safe ) }. |.
      CATCH lcx_predicate INTO DATA(lx).
        cl_abap_unit_assert=>fail( msg = |H: the safe/split predicate path must not raise: { lx->msg }| ).
    ENDTRY.

    lv_msg = lv_msg &&
      |VERDICT: naive-single-row-truncation returned { lines( lt_data_naive ) } row(s) | &&
      |vs the correct/split answer of { lines( lt_data_safe ) } row(s) for TABNAME=DD02L AND FIELDNAME=TABNAME.|.

    cl_abap_unit_assert=>assert_equals( act = lines( lt_data_safe ) exp = 1
      msg = |H: the safe/split path must return exactly the one matching DD03L row: { lv_msg }| ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lines( lt_data_naive ) > lines( lt_data_safe ) )
      msg = |H: the naive truncated path must overcount relative to the safe path: { lv_msg }| ).
  ENDMETHOD.

  METHOD i_select_options_render.
    " Legacy rows (no SIGN) first, each ANDed; then signed rows per field.
    DATA(lv_text) = lcl_predicate_builder=>build_predicate_text( VALUE #(
      ( fieldname = 'tabname' sign = 'I' op = 'EQ' value = 'DD02L' )
      ( fieldname = 'FIELDNAME' op = 'CP' value = `A_#*%+` )
      ( fieldname = 'TABNAME' sign = 'I' op = 'EQ' value = 'DD03L' )
      ( fieldname = 'AS4LOCAL' op = 'GE' value = 'A' )
      ( fieldname = 'FIELDNAME' sign = 'E' op = 'NB' value = 'A' high = `O'Z` )
      ( fieldname = 'AS4LOCAL' op = 'LE' value = 'N' ) ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lv_text
      exp = `FIELDNAME LIKE 'A#_*#%_' ESCAPE '#' AND AS4LOCAL >= 'A' AND AS4LOCAL <= 'N' AND ` &&
            `( TABNAME = 'DD02L' OR TABNAME = 'DD03L' ) AND FIELDNAME BETWEEN 'A' AND 'O''Z'` ).
  ENDMETHOD.

  METHOD j_select_options_dd03l.
    " OR group, pattern and exclude through RFC_READ_TABLE, split into
    " several C(72) rows, against the same filter as static Open SQL.
    DATA lt_fields TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_data   TYPE STANDARD TABLE OF tab512.
    DATA lt_options TYPE ty_options.
    DATA lv_count  TYPE i.

    TRY.
        lt_options = lcl_predicate_builder=>predicate_to_options( VALUE #(
          ( fieldname = 'TABNAME' sign = 'I' op = 'EQ' value = 'DD02L' )
          ( fieldname = 'TABNAME' sign = 'I' op = 'EQ' value = 'DD03L' )
          ( fieldname = 'TABNAME' sign = 'I' op = 'EQ' value = 'DD04L' )
          ( fieldname = 'FIELDNAME' op = 'CP' value = 'AS4*' )
          ( fieldname = 'FIELDNAME' sign = 'E' op = 'EQ' value = 'AS4USER' ) ) ).
      CATCH lcx_predicate INTO DATA(lx).
        cl_abap_unit_assert=>fail( msg = |J: predicate refused: { lx->msg }| ).
    ENDTRY.
    APPEND VALUE #( fieldname = 'TABNAME' ) TO lt_fields.
    APPEND VALUE #( fieldname = 'FIELDNAME' ) TO lt_fields.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD03L' delimiter = '|'
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    DATA(lv_subrc) = sy-subrc.

    SELECT COUNT(*) FROM dd03l
      WHERE ( tabname = 'DD02L' OR tabname = 'DD03L' OR tabname = 'DD04L' )
        AND fieldname LIKE 'AS4%' AND fieldname <> 'AS4USER'.
    lv_count = sy-dbcnt.

    DATA(lv_rows) = ``.
    LOOP AT lt_options INTO DATA(ls_opt).
      lv_rows = |{ lv_rows }[{ ls_opt-text }]|.
      cl_abap_unit_assert=>assert_true( act = xsdbool( strlen( ls_opt-text ) <= 72 ) msg = |J: row [{ ls_opt-text }]| ).
    ENDLOOP.
    cl_abap_unit_assert=>assert_equals( act = lv_subrc exp = 0 msg = |J: RFC_READ_TABLE failed: { lv_rows }| ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lines( lt_options ) > 1 ) msg = |J: expected a split: { lv_rows }| ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lv_count > 0 ) msg = 'J: the oracle selects rows' ).
    cl_abap_unit_assert=>assert_equals( act = lines( lt_data ) exp = lv_count msg = |J: rows vs Open SQL: { lv_rows }| ).
  ENDMETHOD.

ENDCLASS.