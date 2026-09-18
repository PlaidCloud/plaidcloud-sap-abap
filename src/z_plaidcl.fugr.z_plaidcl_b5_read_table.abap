*----------------------------------------------------------------------
* sc-27795 B5 Z_PLAIDCL_B5_READ_TABLE (-> /PLAIDCL/READ_TABLE)
*
* Remote-enabled keyset-cursor read over one transparent table: every
* table extract rides on it. Set "Remote-Enabled Module" on the FM
* attributes; it is not expressible in source.
*
* WIRE CONTRACT
* - IV_TABNAME, IT_KEY_FIELDS, IT_FIELDS, IT_PREDICATES, IV_ROWCOUNT,
*   IV_CONT_STATE, IV_META_ONLY -> ET_DATA, ET_META, EV_ROW_COUNT,
*   EV_MORE, EV_CONT_STATE. plaidlink#222 aligns the agent to these names.
* - ET_DATA: one line per row, lcl_plaidcl_codec=>encode_row of the raw
*   values in ET_META order. No conversion exits, no currency shift.
*   Numbers carry a LEADING minus (-1000.00); DATS/TIMS are the internal
*   digit strings. ET_META (DFIES) carries DATATYPE/CONVEXIT/REFTABLE/
*   REFFIELD/DECIMALS/KEYFLAG so the caller can interpret them, and
*   FIELDTEXT/SCRTEXT_S/SCRTEXT_M/SCRTEXT_L/REPTEXT in the logon language
*   (SY-LANGU, echoed in LANGU) from DD04T, or DD03T FIELDTEXT for a column without a data
*   element. A text not maintained in that language is blank; there is
*   no fallback language.
* - META-ONLY MODE (IV_META_ONLY = 'X'): returns ET_META and reads no
*   rows. IT_KEY_FIELDS, IT_PREDICATES and IV_CONT_STATE must be empty
*   (else INVALID_KEY_FIELDS / INVALID_PREDICATE / INVALID_CONT_STATE);
*   IV_ROWCOUNT is ignored. IT_FIELDS is optional: given, ET_META is those
*   fields (INVALID_FIELD rules as a read, no key column added); empty,
*   ET_META is every column in DD03L order, client column included,
*   includes expanded, no .INCLUDE/.APPEND rows. The table gates of a read
*   still apply (INVALID_TABLE, TABLE_NOT_FOUND, VIEW_NOT_SUPPORTED,
*   NOT_AUTHORIZED). ET_DATA is empty, EV_ROW_COUNT 0, EV_MORE ' ',
*   EV_CONT_STATE empty. Without the flag, an empty IT_KEY_FIELDS is still
*   refused with INVALID_KEY_FIELDS.
* - IT_PREDICATES: codec rows FIELD|SIGN|OPTION|LOW|HIGH with SAP
*   select-option semantics (see lcl_b5_predicate). A legacy FIELD|OP|LOW
*   row (OP EQ NE GT GE LT LE) is still accepted and ANDed as its own term.
*   CP/NP only on character columns. There is no raw WHERE.
* - IT_KEY_FIELDS must be EXACTLY the table's primary key (DD03L
*   KEYFLAG), in any order, without the client column: Open SQL already
*   restricts the read to the logon client.
*   - A missing column makes "K > last" skip every remaining row sharing
*     the last key value (KEY_NOT_UNIQUE).
*   - An extra, nullable column reads a database NULL back as its
*     initial value, and no "K > v OR K = v" branch ever matches a NULL
*     again, so those rows vanish after page 1 (INVALID_KEY_FIELDS).
*   - A CLNT column is refused in IT_KEY_FIELDS; a table with a CLNT key
*     column other than the logon client cannot be paged at all.
* - IV_ROWCOUNT is 1..50000; anything else is refused, never clamped.
* - Page byte budget: DD03L LENG of the effective fields, as wire text,
*   times IV_ROWCOUNT + 1 must stay within 32 MB. Above it the call is
*   refused with ROW_BUDGET_EXCEEDED before the SELECT, never clamped.
*   One page is held about four times over (typed rows, value strings,
*   encoded lines, RFC export), ~130 MB, under a tenth of the ~1.4 GB
*   extended memory of the smallest system this ships to (A4H trial), so a
*   wide table cannot reach TSV_TNEW_PAGE_ALLOC_FAILED. A column without
*   a DDIC length (STRG, RSTR) counts as 65535 characters; a LOB larger
*   than that is not bounded by the estimate.
* - EV_CONT_STATE is opaque and JSONB-safe: pass it back unmodified. It
*   binds the table, the logon client and system, the key column order
*   and a fingerprint of the effective field list and predicates; a
*   mismatch is refused with INVALID_CONT_STATE.
* - A condition in IT_PREDICATES on the client column is refused.
* - Table, field, key and predicate names are [/NS/]NAME: letters, digits
*   and _, with one optional SAP namespace prefix, at most 30 characters in
*   total; anything else is refused.
* - EV_MORE is 'X' or ' '. Compare to 'X'; ' ' is truthy in Python.
* - Every refusal is MESSAGE e001(00) ... RAISING <key>, so the reason
*   survives RFC (a bare RAISE discards all exports).
* - Only TRANSP tables: a view's key is not enforced by the database,
*   and POOL/CLUSTER row order under dynamic Open SQL is unproven.
*----------------------------------------------------------------------

TYPES: BEGIN OF ty_b5_predicate,
         fieldname TYPE string,
         sign      TYPE string,
         option    TYPE string,
         low       TYPE string,
         high      TYPE string,
       END OF ty_b5_predicate,
       ty_b5_predicates TYPE STANDARD TABLE OF ty_b5_predicate WITH DEFAULT KEY,
       ty_b5_value_rows TYPE STANDARD TABLE OF string_table WITH EMPTY KEY.

" Helpers raise this; lcl_b5_orchestrator turns it into a result code
" because a classic-EXCEPTIONS FM cannot TRY/CATCH in its own body.
CLASS lcx_b5 DEFINITION INHERITING FROM cx_static_check FINAL.
  PUBLIC SECTION.
    DATA code TYPE string READ-ONLY.
    DATA msg  TYPE string READ-ONLY.
    METHODS constructor IMPORTING code TYPE string
                                  msg  TYPE string.
ENDCLASS.

CLASS lcx_b5 IMPLEMENTATION.
  METHOD constructor.
    super->constructor( ).
    me->code = code.
    me->msg  = msg.
  ENDMETHOD.
ENDCLASS.

CLASS lcl_b5_sql DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS check_identifier
      IMPORTING iv_name     TYPE string
                iv_code     TYPE string
                iv_allow_ns TYPE abap_bool DEFAULT abap_false
      RAISING   lcx_b5.

    CLASS-METHODS literal
      IMPORTING iv_value      TYPE string
      RETURNING VALUE(rv_sql) TYPE string.
ENDCLASS.

CLASS lcl_b5_sql IMPLEMENTATION.

  METHOD check_identifier.
    " Every DDIC name checked here (table, field, key, predicate, TABCLASS)
    " is at most C30. A longer STRING truncates in a C30 comparison and
    " would match a different, real column.
    IF strlen( iv_name ) > 30.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = iv_code
                  msg  = |Rejected identifier [{ iv_name }]: longer than 30 characters|.
    ENDIF.
    " Letters, digits and _, behind one optional SAP namespace /NS/ when
    " IV_ALLOW_NS. \z, not $: $ also matches before a trailing newline.
    DATA(lv_pattern) = COND string(
      WHEN iv_allow_ns = abap_true THEN '^(/[A-Z0-9][A-Z0-9_]{0,29}/)?[A-Z][A-Z0-9_]{0,29}\z'
      ELSE '^[A-Z][A-Z0-9_]{0,29}\z' ).
    FIND PCRE lv_pattern IN iv_name IGNORING CASE.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = iv_code
                  msg  = |Rejected identifier [{ iv_name }]: not a valid DDIC name|.
    ENDIF.
  ENDMETHOD.

  METHOD literal.
    " An empty value (a blank CHAR key) is written as ' ', not '', so the
    " dynamic WHERE parser never sees two adjacent quotes.
    IF iv_value IS INITIAL.
      rv_sql = `' '`.
      RETURN.
    ENDIF.
    DATA(lv_escaped) = iv_value.
    REPLACE ALL OCCURRENCES OF `'` IN lv_escaped WITH `''`.
    rv_sql = |'{ lv_escaped }'|.
  ENDMETHOD.

ENDCLASS.

*----------------------------------------------------------------------
* IT_PREDICATES follow SAP select-option semantics (sc-28907):
*   FIELD|SIGN|OPTION|LOW|HIGH, SIGN I/E, OPTION EQ NE GT GE LT LE BT NB
*   CP NP. A legacy FIELD|OP|LOW row (OP EQ..LE) keeps its old meaning:
*   decoded with SIGN initial, it is ANDed as its own term.
* Per field: (I1 OR I2 ...) AND NOT E1 AND NOT E2 ...; fields are ANDed.
* An E row renders as the complementary option (NOT F = v is F <> v, and
* both are unknown for a NULL), so only the OR group needs parentheses.
* The result has no top-level OR, so ANDing it into each keyset branch is
* exact. CP/NP: * -> %, + -> _, SAP's #x is a literal x, and a literal
* % _ # is escaped with # (ESCAPE '#').
*----------------------------------------------------------------------
CLASS lcl_b5_predicate DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS decode
      IMPORTING it_wire         TYPE string_table
      RETURNING VALUE(rt_preds) TYPE ty_b5_predicates
      RAISING   lcx_b5.

    CLASS-METHODS to_where
      IMPORTING it_preds       TYPE ty_b5_predicates
      RETURNING VALUE(rv_text) TYPE string
      RAISING   lcx_b5.

    " SAP CP pattern -> SQL LIKE pattern for ESCAPE '#', not yet quoted.
    CLASS-METHODS like_pattern
      IMPORTING iv_value          TYPE string
      RETURNING VALUE(rv_pattern) TYPE string.

  PRIVATE SECTION.
    CLASS-METHODS condition
      IMPORTING is_pred        TYPE ty_b5_predicate
      RETURNING VALUE(rv_text) TYPE string
      RAISING   lcx_b5.
ENDCLASS.

CLASS lcl_b5_predicate IMPLEMENTATION.

  METHOD decode.
    LOOP AT it_wire INTO DATA(lv_line).
      DATA(lv_line_no) = sy-tabix.
      DATA(lt_parts) = lcl_plaidcl_codec=>decode_row( lv_line ).
      CASE lines( lt_parts ).
        WHEN 3.
          IF NOT matches( val = to_upper( lt_parts[ 2 ] ) regex = `EQ|NE|GT|GE|LT|LE` ).
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_PREDICATE'
                        msg  = |IT_PREDICATES line { lv_line_no }: operator [{ lt_parts[ 2 ] }] of a | &&
                               |FIELD\|OP\|LOW row is not one of EQ NE GT GE LT LE|.
          ENDIF.
          " SIGN stays initial: a legacy row keeps its AND meaning (to_where).
          APPEND VALUE #( fieldname = to_upper( lt_parts[ 1 ] )
                          option    = to_upper( lt_parts[ 2 ] )
                          low       = lt_parts[ 3 ] ) TO rt_preds.
        WHEN 5.
          IF lt_parts[ 2 ] IS INITIAL.
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_PREDICATE'
                        msg  = |IT_PREDICATES line { lv_line_no }: SIGN is empty; use I or E|.
          ENDIF.
          APPEND VALUE #( fieldname = to_upper( lt_parts[ 1 ] )
                          sign      = to_upper( lt_parts[ 2 ] )
                          option    = to_upper( lt_parts[ 3 ] )
                          low       = lt_parts[ 4 ]
                          high      = lt_parts[ 5 ] ) TO rt_preds.
        WHEN OTHERS.
          RAISE EXCEPTION TYPE lcx_b5
            EXPORTING code = 'INVALID_PREDICATE'
                      msg  = |IT_PREDICATES line { lv_line_no } has { lines( lt_parts ) } fields; | &&
                             |expected FIELD\|SIGN\|OPTION\|LOW\|HIGH or FIELD\|OP\|LOW|.
      ENDCASE.
    ENDLOOP.
  ENDMETHOD.

  METHOD to_where.
    DATA lt_fields    TYPE string_table.
    DATA lv_cond      TYPE string.
    DATA lv_include   TYPE string.
    DATA lv_exclude   TYPE string.
    DATA lv_includes  TYPE i.
    DATA lv_part      TYPE string.

    LOOP AT it_preds INTO DATA(ls_pred).
      lcl_b5_sql=>check_identifier( iv_name = ls_pred-fieldname iv_code = 'INVALID_PREDICATE' iv_allow_ns = abap_true ).
      IF ls_pred-sign IS INITIAL.
        " Legacy FIELD|OP|LOW: each row is its own AND term, as before
        " sc-28907 (TABNAME GE DD0 + TABNAME LT DD1 is a range, not an OR).
        ls_pred-sign = `I`.
        lv_cond = condition( ls_pred ).
        rv_text = COND #( WHEN rv_text IS INITIAL THEN lv_cond ELSE |{ rv_text } AND { lv_cond }| ).
      ELSEIF NOT line_exists( lt_fields[ table_line = ls_pred-fieldname ] ).
        APPEND ls_pred-fieldname TO lt_fields.
      ENDIF.
    ENDLOOP.

    LOOP AT lt_fields INTO DATA(lv_field).
      CLEAR: lv_include, lv_exclude, lv_includes.
      LOOP AT it_preds INTO ls_pred WHERE fieldname = lv_field AND sign IS NOT INITIAL.
        lv_cond = condition( ls_pred ).
        IF ls_pred-sign = `I`.
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

  METHOD condition.
    DATA(lv_field) = is_pred-fieldname.
    IF is_pred-sign <> `I` AND is_pred-sign <> `E`.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_PREDICATE'
                  msg  = |Predicate on [{ lv_field }]: SIGN [{ is_pred-sign }] is not I or E|.
    ENDIF.
    IF NOT matches( val = is_pred-option regex = `EQ|NE|GT|GE|LT|LE|BT|NB|CP|NP` ).
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_PREDICATE'
                  msg  = |Predicate on [{ lv_field }]: OPTION [{ is_pred-option }] is not one of | &&
                         |EQ NE GT GE LT LE BT NB CP NP|.
    ENDIF.
    DATA(lv_ranged) = xsdbool( is_pred-option = `BT` OR is_pred-option = `NB` ).
    IF lv_ranged = abap_true AND is_pred-high IS INITIAL.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_PREDICATE'
                  msg  = |Predicate on [{ lv_field }]: OPTION { is_pred-option } needs a HIGH value|.
    ENDIF.
    IF lv_ranged = abap_false AND is_pred-high IS NOT INITIAL.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_PREDICATE'
                  msg  = |Predicate on [{ lv_field }]: OPTION { is_pred-option } takes no HIGH value|.
    ENDIF.

    DATA(lv_option) = COND string(
      WHEN is_pred-sign = `I` THEN is_pred-option
      ELSE SWITCH string( is_pred-option
             WHEN `EQ` THEN `NE`
             WHEN `NE` THEN `EQ`
             WHEN `GT` THEN `LE`
             WHEN `GE` THEN `LT`
             WHEN `LT` THEN `GE`
             WHEN `LE` THEN `GT`
             WHEN `BT` THEN `NB`
             WHEN `NB` THEN `BT`
             WHEN `CP` THEN `NP`
             ELSE `CP` ) ).
    DATA(lv_low) = lcl_b5_sql=>literal( is_pred-low ).

    rv_text = SWITCH #( lv_option
      WHEN `EQ` THEN |{ lv_field } = { lv_low }|
      WHEN `NE` THEN |{ lv_field } <> { lv_low }|
      WHEN `GT` THEN |{ lv_field } > { lv_low }|
      WHEN `GE` THEN |{ lv_field } >= { lv_low }|
      WHEN `LT` THEN |{ lv_field } < { lv_low }|
      WHEN `LE` THEN |{ lv_field } <= { lv_low }|
      WHEN `BT` THEN |{ lv_field } BETWEEN { lv_low } AND { lcl_b5_sql=>literal( is_pred-high ) }|
      WHEN `NB` THEN |{ lv_field } NOT BETWEEN { lv_low } AND { lcl_b5_sql=>literal( is_pred-high ) }|
      WHEN `CP` THEN |{ lv_field } LIKE { lcl_b5_sql=>literal( like_pattern( is_pred-low ) ) } ESCAPE '#'|
      ELSE           |{ lv_field } NOT LIKE { lcl_b5_sql=>literal( like_pattern( is_pred-low ) ) } ESCAPE '#'| ).
  ENDMETHOD.

  METHOD like_pattern.
    DATA lv_pos TYPE i.
    DATA(lv_len) = strlen( iv_value ).
    WHILE lv_pos < lv_len.
      DATA(lv_char) = substring( val = iv_value off = lv_pos len = 1 ).
      lv_pos = lv_pos + 1.
      IF lv_char = `#` AND lv_pos < lv_len.
        " SAP's own escape: the next character is literal, even * or +.
        lv_char = substring( val = iv_value off = lv_pos len = 1 ).
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

ENDCLASS.

*----------------------------------------------------------------------
* Continuation token parts, packed by lcl_plaidcl_codec=>encode_token:
*   table | client | system | n | key_1 .. key_n | fingerprint |
*   value_1 .. value_n
* Values are the last row's typed key values converted by
* lcl_b5_reader=>to_text, never re-split out of an encoded ET_DATA line.
*----------------------------------------------------------------------
CLASS lcl_b5_keyset DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS fingerprint
      IMPORTING it_fields      TYPE string_table
                it_preds       TYPE string_table
      RETURNING VALUE(rv_hash) TYPE string
      RAISING   lcx_b5.

    CLASS-METHODS encode_token
      IMPORTING iv_table        TYPE string
                it_keys         TYPE string_table
                iv_fingerprint  TYPE string
                it_values       TYPE string_table
      RETURNING VALUE(rv_token) TYPE string.

    CLASS-METHODS decode_token
      IMPORTING iv_token         TYPE string
                iv_table         TYPE string
                it_keys          TYPE string_table
                iv_fingerprint   TYPE string
      RETURNING VALUE(rt_values) TYPE string_table
      RAISING   lcx_b5.

    " One line per OR branch: K1 > V1 / K1 = V1 AND K2 > V2 / ...
    " The caller ANDs the user predicate into each branch; that predicate
    " has no top-level OR (its OR groups are parenthesised), so this is exact.
    CLASS-METHODS build_terms
      IMPORTING it_keys         TYPE string_table
                it_values       TYPE string_table
      RETURNING VALUE(rt_terms) TYPE string_table.
ENDCLASS.

CLASS lcl_b5_keyset IMPLEMENTATION.

  METHOD fingerprint.
    DATA lt_parts TYPE string_table.
    APPEND |{ lines( it_fields ) }| TO lt_parts.
    APPEND LINES OF it_fields TO lt_parts.
    APPEND LINES OF it_preds TO lt_parts.
    DATA(lv_canonical) = lcl_plaidcl_codec=>encode_row( lt_parts ).
    DATA lv_hash TYPE string.
    TRY.
        cl_abap_message_digest=>calculate_hash_for_char(
          EXPORTING if_algorithm  = 'SHA1'
                    if_data       = lv_canonical
          IMPORTING ef_hashstring = lv_hash ).
      CATCH cx_abap_message_digest INTO DATA(lx_hash).
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INTERNAL_ERROR'
                    msg  = |Fingerprint hash failed: { lx_hash->get_text( ) }|.
    ENDTRY.
    rv_hash = lv_hash.
  ENDMETHOD.

  METHOD encode_token.
    DATA lt_parts TYPE string_table.
    APPEND iv_table TO lt_parts.
    APPEND |{ sy-mandt }| TO lt_parts.
    APPEND |{ sy-sysid }| TO lt_parts.
    APPEND |{ lines( it_keys ) }| TO lt_parts.
    APPEND LINES OF it_keys TO lt_parts.
    APPEND iv_fingerprint TO lt_parts.
    APPEND LINES OF it_values TO lt_parts.
    rv_token = lcl_plaidcl_codec=>encode_token( lt_parts ).
  ENDMETHOD.

  METHOD decode_token.
    DATA(lt_parts) = lcl_plaidcl_codec=>decode_token( iv_token ).
    DATA(lv_n) = lines( it_keys ).
    IF lines( lt_parts ) <> 5 + 2 * lv_n.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_CONT_STATE'
                  msg  = |IV_CONT_STATE is not a token for { lv_n } key column(s); | &&
                         |pass EV_CONT_STATE back unmodified|.
    ENDIF.

    " Replayed on another client or system, the key values would page
    " from a row that client never had and skip its leading rows.
    IF lt_parts[ 2 ] <> |{ sy-mandt }| OR lt_parts[ 3 ] <> |{ sy-sysid }|.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_CONT_STATE'
                  msg  = |IV_CONT_STATE was issued on client { lt_parts[ 2 ] } of system | &&
                         |{ lt_parts[ 3 ] }, not client { sy-mandt } of { sy-sysid }; | &&
                         |restart the read without a token|.
    ENDIF.

    DATA(lv_same) = xsdbool( lt_parts[ 1 ] = iv_table
                         AND lt_parts[ 4 ] = |{ lv_n }|
                         AND lt_parts[ 5 + lv_n ] = iv_fingerprint ).
    DO lv_n TIMES.
      IF lt_parts[ 4 + sy-index ] <> it_keys[ sy-index ].
        lv_same = abap_false.
      ENDIF.
    ENDDO.
    IF lv_same = abap_false.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INVALID_CONT_STATE'
                  msg  = |IV_CONT_STATE was issued for a different table, key column order, | &&
                         |IT_FIELDS or IT_PREDICATES; restart the read without a token|.
    ENDIF.

    DO lv_n TIMES.
      APPEND lt_parts[ 5 + lv_n + sy-index ] TO rt_values.
    ENDDO.
  ENDMETHOD.

  METHOD build_terms.
    DATA(lv_n) = lines( it_keys ).
    DO lv_n TIMES.
      DATA(lv_i) = sy-index.
      DATA(lv_clause) = ``.
      DO lv_i - 1 TIMES.
        DATA(lv_eq) = |{ it_keys[ sy-index ] } = { lcl_b5_sql=>literal( it_values[ sy-index ] ) }|.
        lv_clause = COND #( WHEN lv_clause IS INITIAL THEN lv_eq ELSE |{ lv_clause } AND { lv_eq }| ).
      ENDDO.
      DATA(lv_gt) = |{ it_keys[ lv_i ] } > { lcl_b5_sql=>literal( it_values[ lv_i ] ) }|.
      APPEND COND string( WHEN lv_clause IS INITIAL THEN lv_gt ELSE |{ lv_clause } AND { lv_gt }| ) TO rt_terms.
    ENDDO.
  ENDMETHOD.

ENDCLASS.

CLASS lcl_b5_metadata DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_unbounded_chars TYPE i VALUE 65535.

    " Active version only (AS4LOCAL = 'A', AS4VERS = '0000'): an inactive
    " version in DD03L would otherwise duplicate every column.
    " EV_CLIDEP is DD02L-CLIDEP: Open SQL restricts the first (CLNT)
    " column to the logon client only on a client-dependent table.
    CLASS-METHODS load_columns
      IMPORTING iv_table  TYPE tabname
      EXPORTING et_cols   TYPE dfies_table
                ev_clidep TYPE abap_bool
      RAISING   lcx_b5.

    " IT_KEYS (upper case, no duplicates) must be exactly the primary key,
    " the logon-client column excluded. See the WIRE CONTRACT header.
    CLASS-METHODS check_keys
      IMPORTING it_keys   TYPE string_table
                it_cols   TYPE dfies_table
                iv_clidep TYPE abap_bool
                iv_table  TYPE string
      RAISING   lcx_b5.

    " Estimated bytes one row of IT_META takes as wire text (UTF-16): RAW
    " is hex, a number gets room for sign, point and exponent, and a
    " column without a DDIC length counts as c_unbounded_chars.
    CLASS-METHODS row_bytes
      IMPORTING it_meta         TYPE dfies_table
      RETURNING VALUE(rv_bytes) TYPE int8.

    CLASS-METHODS fill_convexits
      CHANGING ct_meta TYPE dfies_table.

    " Logon language only: a missing text stays blank.
    CLASS-METHODS fill_texts
      CHANGING ct_meta TYPE dfies_table.
ENDCLASS.

CLASS lcl_b5_metadata IMPLEMENTATION.

  METHOD load_columns.
    DATA lv_local TYPE dd03l-as4local VALUE 'A'.
    DATA lv_vers  TYPE dd03l-as4vers VALUE '0000'.
    CLEAR: et_cols, ev_clidep.

    SELECT SINGLE tabclass, clidep FROM dd02l
      WHERE tabname = @iv_table AND as4local = @lv_local AND as4vers = @lv_vers
      INTO @DATA(ls_dd02l).
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'TABLE_NOT_FOUND'
                  msg  = |No active DD02L entry for [{ iv_table }]|.
    ENDIF.
    IF ls_dd02l-tabclass <> 'TRANSP'.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'VIEW_NOT_SUPPORTED'
                  msg  = |[{ iv_table }] is TABCLASS { ls_dd02l-tabclass }; only TRANSP tables are read|.
    ENDIF.
    ev_clidep = ls_dd02l-clidep.

    SELECT fieldname, position, keyflag, rollname, domname, datatype,
           inttype, leng, decimals, reftable, reffield
      FROM dd03l
      WHERE tabname = @iv_table AND as4local = @lv_local AND as4vers = @lv_vers
      ORDER BY position
      INTO TABLE @DATA(lt_dd03l).

    " .INCLUDE / .APPEND marker rows; their fields are listed individually.
    LOOP AT lt_dd03l INTO DATA(ls_col).
      IF ls_col-fieldname CP '.*'.
        CONTINUE.
      ENDIF.
      APPEND VALUE #( tabname  = iv_table
                      fieldname = ls_col-fieldname
                      position = ls_col-position
                      keyflag  = ls_col-keyflag
                      rollname = ls_col-rollname
                      domname  = ls_col-domname
                      datatype = ls_col-datatype
                      inttype  = ls_col-inttype
                      leng     = ls_col-leng
                      decimals = ls_col-decimals
                      reftable = ls_col-reftable
                      reffield = ls_col-reffield ) TO et_cols.
    ENDLOOP.

    IF et_cols IS INITIAL.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'TABLE_NOT_FOUND'
                  msg  = |[{ iv_table }] has no active DD03L columns|.
    ENDIF.
  ENDMETHOD.

  METHOD check_keys.
    DATA lt_pk      TYPE string_table.
    DATA lv_missing TYPE string.
    DATA lv_extra   TYPE string.

    DATA(lv_first) = abap_true.
    LOOP AT it_cols INTO DATA(ls_col) WHERE keyflag = abap_true.
      IF ls_col-datatype <> 'CLNT'.
        APPEND CONV string( ls_col-fieldname ) TO lt_pk.
      ELSEIF lv_first = abap_false OR iv_clidep = abap_false.
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INVALID_KEY_FIELDS'
                    msg  = |[{ iv_table }] key column { ls_col-fieldname } is CLNT but not the logon | &&
                           |client; this table cannot be paged|.
      ENDIF.
      lv_first = abap_false.
    ENDLOOP.

    LOOP AT it_keys INTO DATA(lv_key).
      DATA(lv_index) = line_index( it_cols[ fieldname = lv_key ] ).
      IF lv_index = 0.
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INVALID_KEY_FIELDS'
                    msg  = |Key column [{ lv_key }] does not exist on [{ iv_table }]|.
      ENDIF.
      IF it_cols[ lv_index ]-datatype = 'CLNT'.
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INVALID_KEY_FIELDS'
                    msg  = |Key column [{ lv_key }] of [{ iv_table }] is a CLNT column; leave it out, | &&
                           |Open SQL reads the logon client only|.
      ENDIF.
      IF NOT line_exists( lt_pk[ table_line = lv_key ] ).
        lv_extra = |{ lv_extra } { lv_key }|.
      ENDIF.
    ENDLOOP.

    LOOP AT lt_pk INTO DATA(lv_pk).
      IF NOT line_exists( it_keys[ table_line = lv_pk ] ).
        lv_missing = |{ lv_missing } { lv_pk }|.
      ENDIF.
    ENDLOOP.

    IF lv_missing IS INITIAL AND lv_extra IS INITIAL.
      RETURN.
    ENDIF.
    RAISE EXCEPTION TYPE lcx_b5
      EXPORTING code = COND #( WHEN lv_missing IS NOT INITIAL THEN `KEY_NOT_UNIQUE` ELSE `INVALID_KEY_FIELDS` )
                msg  = |IT_KEY_FIELDS must be exactly the primary key of [{ iv_table }] without the | &&
                       |client column. Missing:{ lv_missing }. Extra:{ lv_extra }.|.
  ENDMETHOD.

  METHOD row_bytes.
    LOOP AT it_meta INTO DATA(ls_col).
      DATA(lv_chars) = CONV int8( ls_col-leng ).
      IF lv_chars = 0.
        lv_chars = c_unbounded_chars.
      ELSEIF ls_col-inttype CA 'Xy'.
        lv_chars = 2 * lv_chars.
      ELSEIF ls_col-inttype CA 'PIbs8aeF'.
        lv_chars = lv_chars + 24.
      ENDIF.
      rv_bytes = rv_bytes + 2 * lv_chars.
    ENDLOOP.
  ENDMETHOD.

  METHOD fill_convexits.
    DATA lv_local TYPE dd01l-as4local VALUE 'A'.
    DATA lv_vers  TYPE dd01l-as4vers VALUE '0000'.
    DATA(lt_meta) = ct_meta.
    DELETE lt_meta WHERE domname IS INITIAL.
    IF lt_meta IS INITIAL.
      RETURN.
    ENDIF.

    SELECT domname, convexit FROM dd01l
      FOR ALL ENTRIES IN @lt_meta
      WHERE domname = @lt_meta-domname AND as4local = @lv_local AND as4vers = @lv_vers
      INTO TABLE @DATA(lt_conv).

    LOOP AT ct_meta ASSIGNING FIELD-SYMBOL(<ls_meta>) WHERE domname IS NOT INITIAL.
      READ TABLE lt_conv INTO DATA(ls_conv) WITH KEY domname = <ls_meta>-domname.
      IF sy-subrc = 0.
        <ls_meta>-convexit = ls_conv-convexit.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD fill_texts.
    DATA lv_local TYPE dd04t-as4local VALUE 'A'.
    DATA lv_vers  TYPE dd04t-as4vers VALUE '0000'.
    DATA lv_langu TYPE dd04t-ddlanguage.
    lv_langu = sy-langu.

    DATA(lt_rolled) = ct_meta.
    DELETE lt_rolled WHERE rollname IS INITIAL.
    IF lt_rolled IS NOT INITIAL.
      SELECT rollname, ddtext, reptext, scrtext_s, scrtext_m, scrtext_l FROM dd04t
        FOR ALL ENTRIES IN @lt_rolled
        WHERE rollname = @lt_rolled-rollname AND ddlanguage = @lv_langu
          AND as4local = @lv_local AND as4vers = @lv_vers
        INTO TABLE @DATA(lt_dd04t).
    ENDIF.

    " A column typed directly (no data element) has only a DD03T text.
    DATA(lt_plain) = ct_meta.
    DELETE lt_plain WHERE rollname IS NOT INITIAL.
    IF lt_plain IS NOT INITIAL.
      SELECT fieldname, ddtext FROM dd03t
        FOR ALL ENTRIES IN @lt_plain
        WHERE tabname = @lt_plain-tabname AND fieldname = @lt_plain-fieldname
          AND ddlanguage = @lv_langu AND as4local = @lv_local
        INTO TABLE @DATA(lt_dd03t).
    ENDIF.

    SORT lt_dd04t BY rollname.
    SORT lt_dd03t BY fieldname.
    LOOP AT ct_meta ASSIGNING FIELD-SYMBOL(<ls_meta>).
      <ls_meta>-langu = sy-langu.
      IF <ls_meta>-rollname IS NOT INITIAL.
        READ TABLE lt_dd04t INTO DATA(ls_dd04t) WITH KEY rollname = <ls_meta>-rollname BINARY SEARCH.
        IF sy-subrc = 0.
          <ls_meta>-fieldtext = ls_dd04t-ddtext.
          <ls_meta>-reptext   = ls_dd04t-reptext.
          <ls_meta>-scrtext_s = ls_dd04t-scrtext_s.
          <ls_meta>-scrtext_m = ls_dd04t-scrtext_m.
          <ls_meta>-scrtext_l = ls_dd04t-scrtext_l.
        ENDIF.
      ELSE.
        READ TABLE lt_dd03t INTO DATA(ls_dd03t) WITH KEY fieldname = <ls_meta>-fieldname BINARY SEARCH.
        IF sy-subrc = 0.
          <ls_meta>-fieldtext = ls_dd03t-ddtext.
        ENDIF.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

*----------------------------------------------------------------------
* Dynamic reader. The row type is built from the table's own RTTI
* component types (a STRING target breaks on DATS columns, proven live)
* with synthetic names F1..Fn; rows are read positionally.
*----------------------------------------------------------------------
CLASS lcl_b5_reader DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS read_rows
      IMPORTING iv_table       TYPE tabname
                it_columns     TYPE string_table
                iv_where       TYPE string
                iv_order_by    TYPE string
                iv_max_rows    TYPE i
      RETURNING VALUE(rt_rows) TYPE ty_b5_value_rows
      RAISING   lcx_b5.

    " CONV gives the format-independent value, but puts a numeric sign
    " at the END (1000.00-); the wire contract wants it in front.
    CLASS-METHODS to_text
      IMPORTING iv_value       TYPE simple
                iv_numeric     TYPE abap_bool
      RETURNING VALUE(rv_text) TYPE string.
ENDCLASS.

CLASS lcl_b5_reader IMPLEMENTATION.

  METHOD read_rows.
    DATA lt_components TYPE cl_abap_structdescr=>component_table.
    DATA lt_numeric    TYPE STANDARD TABLE OF abap_bool WITH EMPTY KEY.
    DATA lr_rows       TYPE REF TO data.
    DATA lv_colnum     TYPE i.
    FIELD-SYMBOLS <lt_rows> TYPE STANDARD TABLE.

    " get_components() returns an .INCLUDE/.APPEND as ONE structured
    " component, so its fields are not found there. The included view is
    " flat.
    DATA lo_descr TYPE REF TO cl_abap_typedescr.
    CALL METHOD cl_abap_typedescr=>describe_by_name
      EXPORTING  p_name         = iv_table
      RECEIVING  p_descr_ref    = lo_descr
      EXCEPTIONS type_not_found = 1
                 OTHERS         = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE lcx_b5
        EXPORTING code = 'INTERNAL_ERROR'
                  msg  = |No runtime type for [{ iv_table }]|.
    ENDIF.
    DATA(lo_table) = CAST cl_abap_structdescr( lo_descr ).
    DATA(lt_view) = lo_table->get_included_view( ).

    LOOP AT it_columns INTO DATA(lv_column).
      lv_colnum = lv_colnum + 1.
      DATA(lv_index) = line_index( lt_view[ name = lv_column ] ).
      IF lv_index = 0.
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INTERNAL_ERROR'
                    msg  = |Column [{ lv_column }] is in DD03L but not in the runtime type of [{ iv_table }]|.
      ENDIF.
      DATA(lo_type) = lt_view[ lv_index ]-type.
      IF lo_type->kind <> cl_abap_typedescr=>kind_elem.
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INVALID_FIELD'
                    msg  = |Column [{ lv_column }] of [{ iv_table }] is not elementary | &&
                           |(RTTI kind { lo_type->kind }) and cannot be serialized|.
      ENDIF.
      APPEND VALUE #( name = |F{ lv_colnum }| type = lo_type ) TO lt_components.
      " P I b s 8 a e F: packed, int, int1, int2, int8, decfloat16/34, float.
      APPEND xsdbool( lo_type->type_kind CA 'PIbs8aeF' ) TO lt_numeric.
    ENDLOOP.

    TRY.
        DATA(lo_row_type) = cl_abap_structdescr=>create( lt_components ).
        DATA(lo_tab_type) = cl_abap_tabledescr=>create( p_line_type = lo_row_type ).
        CREATE DATA lr_rows TYPE HANDLE lo_tab_type.
      CATCH cx_root INTO DATA(lx_rtti).
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INTERNAL_ERROR'
                    msg  = |Row type construction failed: { lx_rtti->get_text( ) }|.
    ENDTRY.
    ASSIGN lr_rows->* TO <lt_rows>.

    DATA(lv_cols) = concat_lines_of( table = it_columns sep = `, ` ).
    TRY.
        SELECT (lv_cols)
          FROM (iv_table)
          WHERE (iv_where)
          ORDER BY (iv_order_by)
          INTO TABLE @<lt_rows>
          UP TO @iv_max_rows ROWS.
      CATCH cx_root INTO DATA(lx_sql).
        RAISE EXCEPTION TYPE lcx_b5
          EXPORTING code = 'INTERNAL_ERROR'
                    msg  = |SELECT on [{ iv_table }] failed: { lx_sql->get_text( ) } where=[{ iv_where }]|.
    ENDTRY.

    DATA(lv_ncols) = lines( it_columns ).
    LOOP AT <lt_rows> ASSIGNING FIELD-SYMBOL(<ls_row>).
      DATA lt_values TYPE string_table.
      CLEAR lt_values.
      DO lv_ncols TIMES.
        DATA(lv_col) = sy-index.
        ASSIGN COMPONENT lv_col OF STRUCTURE <ls_row> TO FIELD-SYMBOL(<lv_value>).
        APPEND to_text( iv_value = <lv_value> iv_numeric = lt_numeric[ lv_col ] ) TO lt_values.
      ENDDO.
      APPEND lt_values TO rt_rows.
    ENDLOOP.
  ENDMETHOD.

  METHOD to_text.
    rv_text = CONV string( iv_value ).
    IF iv_numeric = abap_false.
      RETURN.
    ENDIF.
    CONDENSE rv_text NO-GAPS.
    DATA(lv_len) = strlen( rv_text ).
    IF lv_len > 1 AND substring( val = rv_text off = lv_len - 1 len = 1 ) = `-`.
      rv_text = |-{ substring( val = rv_text len = lv_len - 1 ) }|.
    ENDIF.
  ENDMETHOD.

ENDCLASS.

CLASS lcl_b5_orchestrator DEFINITION FINAL.
  PUBLIC SECTION.
    TYPES: BEGIN OF ty_result,
             data       TYPE string_table,
             meta       TYPE dfies_table,
             row_count  TYPE i,
             more       TYPE abap_bool,
             cont_state TYPE string,
             error_code TYPE string,
             msgv1      TYPE symsgv,
             msgv2      TYPE symsgv,
             msgv3      TYPE symsgv,
             msgv4      TYPE symsgv,
           END OF ty_result.

    CONSTANTS c_max_row_count TYPE i VALUE 50000.
    CONSTANTS c_page_byte_budget TYPE int8 VALUE 33554432.

    CLASS-METHODS run
      IMPORTING iv_tabname       TYPE tabname
                it_key_fields    TYPE string_table
                it_fields        TYPE string_table
                it_predicates    TYPE string_table
                iv_rowcount      TYPE i
                iv_cont_state    TYPE string
                iv_meta_only     TYPE abap_bool
      RETURNING VALUE(rs_result) TYPE ty_result.
ENDCLASS.

CLASS lcl_b5_orchestrator IMPLEMENTATION.

  METHOD run.
    TRY.
        IF iv_meta_only = abap_false AND ( iv_rowcount < 1 OR iv_rowcount > c_max_row_count ).
          RAISE EXCEPTION TYPE lcx_b5
            EXPORTING code = 'INVALID_ROWCOUNT'
                      msg  = |IV_ROWCOUNT { iv_rowcount } is outside 1..{ c_max_row_count }|.
        ENDIF.

        " A template trims the C(30) padding that CONV string would keep.
        DATA(lv_table) = to_upper( |{ iv_tabname }| ).
        lcl_b5_sql=>check_identifier( iv_name = lv_table iv_code = 'INVALID_TABLE' iv_allow_ns = abap_true ).
        DATA(lv_table_name) = CONV tabname( lv_table ).

        IF iv_meta_only = abap_true.
          IF it_key_fields IS NOT INITIAL.
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_KEY_FIELDS'
                        msg  = |IT_KEY_FIELDS is not allowed in meta-only mode; leave it empty|.
          ENDIF.
          IF it_predicates IS NOT INITIAL.
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_PREDICATE'
                        msg  = |IT_PREDICATES is not allowed in meta-only mode; leave it empty|.
          ENDIF.
          IF iv_cont_state IS NOT INITIAL.
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_CONT_STATE'
                        msg  = |IV_CONT_STATE is not allowed in meta-only mode; leave it empty|.
          ENDIF.
        ELSEIF it_key_fields IS INITIAL.
          RAISE EXCEPTION TYPE lcx_b5
            EXPORTING code = 'INVALID_KEY_FIELDS'
                      msg  = |IT_KEY_FIELDS is empty; a keyset cursor needs the primary key|.
        ENDIF.
        DATA lt_keys TYPE string_table.
        LOOP AT it_key_fields INTO DATA(lv_key_in).
          lcl_b5_sql=>check_identifier( iv_name = lv_key_in iv_code = 'INVALID_KEY_FIELDS' iv_allow_ns = abap_true ).
          DATA(lv_key_upper) = to_upper( lv_key_in ).
          IF line_exists( lt_keys[ table_line = lv_key_upper ] ).
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_KEY_FIELDS'
                        msg  = |Key column [{ lv_key_upper }] is listed twice in IT_KEY_FIELDS|.
          ENDIF.
          APPEND lv_key_upper TO lt_keys.
        ENDLOOP.

        DATA lt_fields TYPE string_table.
        LOOP AT it_fields INTO DATA(lv_field_in).
          lcl_b5_sql=>check_identifier( iv_name = lv_field_in iv_code = 'INVALID_FIELD' iv_allow_ns = abap_true ).
          APPEND to_upper( lv_field_in ) TO lt_fields.
        ENDLOOP.

        " Contract 1: the caller's own SAP display authorization, before
        " anything about the table is read.
        CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_TABLE'
          EXPORTING
            iv_table_name   = lv_table_name
          EXCEPTIONS
            not_authorized  = 1
            table_not_found = 2
            OTHERS          = 3.
        IF sy-subrc <> 0.
          " The gate's own text names the object it checked, so Basis
          " grants the right one.
          DATA(lv_gate_subrc) = sy-subrc.
          DATA lv_reason TYPE string.
          CONCATENATE sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO lv_reason RESPECTING BLANKS.
          lv_reason = replace( val = lv_reason pcre = `\s+$` with = `` ).
          IF lv_reason IS INITIAL.
            lv_reason = `Z_PLAIDCL_B10_CHECK_TABLE refused without a message`.
          ENDIF.
          RAISE EXCEPTION TYPE lcx_b5
            EXPORTING code = COND #( WHEN lv_gate_subrc = 2 THEN `TABLE_NOT_FOUND` ELSE `NOT_AUTHORIZED` )
                      msg  = |[{ lv_table }] { lv_reason }|.
        ENDIF.

        DATA lt_all_cols TYPE dfies_table.
        DATA lv_clidep TYPE abap_bool.
        lcl_b5_metadata=>load_columns( EXPORTING iv_table  = lv_table_name
                                       IMPORTING et_cols   = lt_all_cols
                                                 ev_clidep = lv_clidep ).
        IF iv_meta_only = abap_false.
          lcl_b5_metadata=>check_keys( it_keys = lt_keys it_cols = lt_all_cols
                                       iv_clidep = lv_clidep iv_table = lv_table ).
        ENDIF.

        " Key columns are force-included: the next token is built from them.
        " In meta-only mode LT_KEYS is empty, so IT_FIELDS is taken as given.
        DATA lv_key TYPE string.
        DATA lt_effective TYPE string_table.
        IF lt_fields IS INITIAL.
          LOOP AT lt_all_cols INTO DATA(ls_all_col).
            APPEND CONV string( ls_all_col-fieldname ) TO lt_effective.
          ENDLOOP.
        ELSE.
          LOOP AT lt_fields INTO DATA(lv_field).
            IF NOT line_exists( lt_all_cols[ fieldname = lv_field ] ).
              RAISE EXCEPTION TYPE lcx_b5
                EXPORTING code = 'INVALID_FIELD'
                          msg  = |Field [{ lv_field }] does not exist on [{ lv_table }]|.
            ENDIF.
            IF NOT line_exists( lt_effective[ table_line = lv_field ] ).
              APPEND lv_field TO lt_effective.
            ENDIF.
          ENDLOOP.
          LOOP AT lt_keys INTO lv_key.
            IF NOT line_exists( lt_effective[ table_line = lv_key ] ).
              APPEND lv_key TO lt_effective.
            ENDIF.
          ENDLOOP.
        ENDIF.

        DATA lv_position TYPE i.
        LOOP AT lt_effective INTO DATA(lv_meta_name).
          lv_position = lv_position + 1.
          DATA(ls_meta) = lt_all_cols[ fieldname = lv_meta_name ].
          ls_meta-position = lv_position.
          APPEND ls_meta TO rs_result-meta.
        ENDLOOP.
        lcl_b5_metadata=>fill_convexits( CHANGING ct_meta = rs_result-meta ).
        lcl_b5_metadata=>fill_texts( CHANGING ct_meta = rs_result-meta ).
        IF iv_meta_only = abap_true.
          RETURN.
        ENDIF.

        DATA(lv_row_bytes) = lcl_b5_metadata=>row_bytes( rs_result-meta ).
        IF lv_row_bytes * ( iv_rowcount + 1 ) > c_page_byte_budget.
          RAISE EXCEPTION TYPE lcx_b5
            EXPORTING code = 'ROW_BUDGET_EXCEEDED'
                      msg  = |[{ lv_table }] rows are ~{ lv_row_bytes } bytes each; { iv_rowcount } of them | &&
                             |exceed the { c_page_byte_budget } byte page budget. At most | &&
                             |{ c_page_byte_budget DIV lv_row_bytes - 1 } fit: lower IV_ROWCOUNT or narrow IT_FIELDS|.
        ENDIF.

        DATA(lt_preds) = lcl_b5_predicate=>decode( it_predicates ).
        LOOP AT lt_preds INTO DATA(ls_pred).
          DATA(lv_pred_col) = line_index( lt_all_cols[ fieldname = ls_pred-fieldname ] ).
          IF lv_pred_col = 0.
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_PREDICATE'
                        msg  = |Predicate field [{ ls_pred-fieldname }] does not exist on [{ lv_table }]|.
          ENDIF.
          " Open SQL adds the logon client itself; a condition on that
          " column would at best empty the result silently.
          IF lv_clidep = abap_true AND lv_pred_col = 1 AND lt_all_cols[ 1 ]-datatype = 'CLNT'.
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_PREDICATE'
                        msg  = |Predicate field [{ ls_pred-fieldname }] is the client column of [{ lv_table }]; | &&
                               |the read is already restricted to the logon client|.
          ENDIF.
          " LIKE on a number or raw column is an SQL error, not a filter.
          IF ( ls_pred-option = `CP` OR ls_pred-option = `NP` )
             AND NOT matches( val = |{ lt_all_cols[ lv_pred_col ]-datatype }|
                              regex = `CHAR|NUMC|DATS|TIMS|LANG|CUKY|UNIT|ACCP|SSTR|CLNT` ).
            RAISE EXCEPTION TYPE lcx_b5
              EXPORTING code = 'INVALID_PREDICATE'
                        msg  = |Predicate field [{ ls_pred-fieldname }] of [{ lv_table }] is | &&
                               |{ lt_all_cols[ lv_pred_col ]-datatype }; CP/NP need a character column|.
          ENDIF.
        ENDLOOP.
        DATA(lv_user_where) = lcl_b5_predicate=>to_where( lt_preds ).
        DATA(lv_fingerprint) = lcl_b5_keyset=>fingerprint( it_fields = it_fields it_preds = it_predicates ).

        DATA lt_keyset_terms TYPE string_table.
        IF iv_cont_state IS NOT INITIAL.
          lt_keyset_terms = lcl_b5_keyset=>build_terms(
            it_keys   = lt_keys
            it_values = lcl_b5_keyset=>decode_token( iv_token       = iv_cont_state
                                                     iv_table       = lv_table
                                                     it_keys        = lt_keys
                                                     iv_fingerprint = lv_fingerprint ) ).
        ENDIF.

        " (k1 > v1 OR k1 = v1 AND k2 > v2) AND pred, written without
        " parentheses by ANDing pred into every OR branch.
        DATA lv_where TYPE string.
        IF lt_keyset_terms IS INITIAL.
          lv_where = lv_user_where.
        ELSE.
          LOOP AT lt_keyset_terms INTO DATA(lv_term).
            IF lv_user_where IS NOT INITIAL.
              lv_term = |{ lv_term } AND { lv_user_where }|.
            ENDIF.
            lv_where = COND #( WHEN lv_where IS INITIAL THEN lv_term ELSE |{ lv_where } OR { lv_term }| ).
          ENDLOOP.
        ENDIF.
        IF lv_where IS INITIAL.
          lv_where = `1 = 1`.
        ENDIF.

        DATA lv_order_by TYPE string.
        LOOP AT lt_keys INTO lv_key.
          lv_order_by = COND #( WHEN lv_order_by IS INITIAL THEN |{ lv_key } ASCENDING|
                                ELSE |{ lv_order_by }, { lv_key } ASCENDING| ).
        ENDLOOP.

        " One row beyond the page tells us EV_MORE without a COUNT(*).
        DATA(lt_rows) = lcl_b5_reader=>read_rows(
          iv_table    = lv_table_name
          it_columns  = lt_effective
          iv_where    = lv_where
          iv_order_by = lv_order_by
          iv_max_rows = iv_rowcount + 1 ).

        LOOP AT lt_rows INTO DATA(lt_row_values) TO iv_rowcount.
          APPEND lcl_plaidcl_codec=>encode_row( lt_row_values ) TO rs_result-data.
        ENDLOOP.
        rs_result-row_count = lines( rs_result-data ).
        rs_result-more = xsdbool( lines( lt_rows ) > iv_rowcount ).

        IF rs_result-more = abap_true.
          DATA(lt_last) = lt_rows[ iv_rowcount ].
          DATA lt_key_values TYPE string_table.
          LOOP AT lt_keys INTO lv_key.
            APPEND lt_last[ line_index( lt_effective[ table_line = lv_key ] ) ] TO lt_key_values.
          ENDLOOP.
          rs_result-cont_state = lcl_b5_keyset=>encode_token(
            iv_table       = lv_table
            it_keys        = lt_keys
            iv_fingerprint = lv_fingerprint
            it_values      = lt_key_values ).
        ENDIF.

      CATCH lcx_b5 INTO DATA(lx).
        DATA(lv_code) = lx->code.
        DATA(lv_rest) = lx->msg.
      CATCH cx_root INTO DATA(lx_root).
        " Anything unforeseen (e.g. CX_SY_MOVE_CAST_ERROR) must still reach
        " the caller as a named key with its text, never as a dump.
        lv_code = `INTERNAL_ERROR`.
        lv_rest = |{ cl_abap_classdescr=>get_class_name( lx_root ) }: { lx_root->get_text( ) }|.
    ENDTRY.

    IF lv_code IS NOT INITIAL.
      CLEAR rs_result.
      rs_result-error_code = lv_code.
      " The group's chunker never ends a chunk on a blank (MESSAGE drops it).
      lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = lv_rest
                                     IMPORTING ev_v1 = rs_result-msgv1 ev_v2 = rs_result-msgv2
                                               ev_v3 = rs_result-msgv3 ev_v4 = rs_result-msgv4 ).
    ENDIF.
  ENDMETHOD.

ENDCLASS.

FUNCTION z_plaidcl_b5_read_table.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TABNAME) TYPE  TABNAME
*"     VALUE(IT_KEY_FIELDS) TYPE  STRING_TABLE
*"     VALUE(IT_FIELDS) TYPE  STRING_TABLE OPTIONAL
*"     VALUE(IT_PREDICATES) TYPE  STRING_TABLE OPTIONAL
*"     VALUE(IV_ROWCOUNT) TYPE  I DEFAULT 1000
*"     VALUE(IV_CONT_STATE) TYPE  STRING OPTIONAL
*"     VALUE(IV_META_ONLY) TYPE  BOOLE_D DEFAULT ' '
*"  EXPORTING
*"     VALUE(ET_DATA) TYPE  STRING_TABLE
*"     VALUE(ET_META) TYPE  DFIES_TABLE
*"     VALUE(EV_ROW_COUNT) TYPE  I
*"     VALUE(EV_MORE) TYPE  BOOLE_D
*"     VALUE(EV_CONT_STATE) TYPE  STRING
*"  EXCEPTIONS
*"      INVALID_TABLE
*"      TABLE_NOT_FOUND
*"      VIEW_NOT_SUPPORTED
*"      NOT_AUTHORIZED
*"      INVALID_KEY_FIELDS
*"      KEY_NOT_UNIQUE
*"      INVALID_FIELD
*"      INVALID_PREDICATE
*"      INVALID_CONT_STATE
*"      INVALID_ROWCOUNT
*"      INTERNAL_ERROR
*"      ROW_BUDGET_EXCEEDED
*"----------------------------------------------------------------------



  CLEAR: et_data, et_meta, ev_row_count, ev_cont_state.
  ev_more = abap_false.

  DATA(ls_run) = lcl_b5_orchestrator=>run(
    iv_tabname    = iv_tabname
    it_key_fields = it_key_fields
    it_fields     = it_fields
    it_predicates = it_predicates
    iv_rowcount   = iv_rowcount
    iv_cont_state = iv_cont_state
    " Only 'X' selects meta-only; any other value is a normal, fully checked read.
    iv_meta_only  = xsdbool( iv_meta_only = abap_true ) ).

  CASE ls_run-error_code.
    WHEN ''.
      et_data       = ls_run-data.
      et_meta       = ls_run-meta.
      ev_row_count  = ls_run-row_count.
      ev_more       = ls_run-more.
      ev_cont_state = ls_run-cont_state.
    WHEN 'INVALID_TABLE'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING invalid_table.
    WHEN 'TABLE_NOT_FOUND'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING table_not_found.
    WHEN 'VIEW_NOT_SUPPORTED'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING view_not_supported.
    WHEN 'NOT_AUTHORIZED'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING not_authorized.
    WHEN 'INVALID_KEY_FIELDS'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING invalid_key_fields.
    WHEN 'KEY_NOT_UNIQUE'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING key_not_unique.
    WHEN 'INVALID_FIELD'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING invalid_field.
    WHEN 'INVALID_PREDICATE'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING invalid_predicate.
    WHEN 'INVALID_CONT_STATE'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING invalid_cont_state.
    WHEN 'INVALID_ROWCOUNT'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING invalid_rowcount.
    WHEN 'ROW_BUDGET_EXCEEDED'.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING row_budget_exceeded.
    WHEN OTHERS.
      MESSAGE e001(00) WITH ls_run-msgv1 ls_run-msgv2 ls_run-msgv3 ls_run-msgv4 RAISING internal_error.
  ENDCASE.

ENDFUNCTION.

*----------------------------------------------------------------------
* Pure-logic unit tests. Live behaviour (gate, DDIC, SELECT, RFC) is in
* z_plaidcl_b5_verify.abap.
*----------------------------------------------------------------------
CLASS ltcl_b5 DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS:
      rejects_injection_identifier FOR TESTING,
      rejects_unknown_operator FOR TESTING,
      where_escapes_quotes FOR TESTING RAISING lcx_b5,
      predicate_value_with_pipe FOR TESTING RAISING lcx_b5,
      token_round_trips_hard_values FOR TESTING RAISING lcx_b5,
      token_refuses_swapped_keys FOR TESTING RAISING lcx_b5,
      token_refuses_other_fprint FOR TESTING RAISING lcx_b5,
      token_refuses_other_table FOR TESTING RAISING lcx_b5,
      token_refuses_garbage FOR TESTING,
      token_refuses_other_client FOR TESTING,
      token_is_jsonb_safe FOR TESTING RAISING lcx_b5,
      fingerprint_tracks_inputs FOR TESTING RAISING lcx_b5,
      terms_composite_key FOR TESTING,
      negative_packed_leading_minus FOR TESTING,
      keys_exact_any_order FOR TESTING RAISING lcx_b5,
      keys_refuse_superset FOR TESTING,
      keys_refuse_missing FOR TESTING,
      keys_refuse_client_column FOR TESTING,
      keys_refuse_other_clnt FOR TESTING,
      identifier_namespace_syntax FOR TESTING RAISING lcx_b5,
      where_namespaced_field FOR TESTING RAISING lcx_b5,
      where_select_options FOR TESTING RAISING lcx_b5,
      like_pattern_escapes FOR TESTING,
      identifier_length_limit FOR TESTING RAISING lcx_b5.

    METHODS expect_refusal
      IMPORTING iv_token TYPE string
                iv_table TYPE string
                it_keys  TYPE string_table
                iv_fp    TYPE string.

    " MANDT (client) MATNR WERKS key; ERDAT is a non-key, nullable column.
    METHODS client_table
      RETURNING VALUE(rt_cols) TYPE dfies_table.

    METHODS expect_key_refusal
      IMPORTING it_keys   TYPE string_table
                it_cols   TYPE dfies_table
                iv_clidep TYPE abap_bool DEFAULT abap_true
                iv_code   TYPE string
                iv_text   TYPE string.
ENDCLASS.

CLASS ltcl_b5 IMPLEMENTATION.

  METHOD rejects_injection_identifier.
    TRY.
        lcl_b5_sql=>check_identifier( iv_name = `TABNAME; DROP TABLE X` iv_code = `INVALID_FIELD` ).
        cl_abap_unit_assert=>fail( msg = 'injection-shaped identifier was accepted' ).
      CATCH lcx_b5 INTO DATA(lx).
        cl_abap_unit_assert=>assert_equals( act = lx->code exp = `INVALID_FIELD` ).
    ENDTRY.
  ENDMETHOD.

  METHOD rejects_unknown_operator.
    " Malformed rows of either shape, each refused as INVALID_PREDICATE.
    DATA(lt_bad) = VALUE string_table(
      ( `TABNAME|DROP|x` )       " legacy row, unknown operator
      ( `TABNAME|BT|x` )         " legacy row cannot carry BT
      ( `TABNAME|X|EQ|x|` )      " SIGN not I/E
      ( `TABNAME|I|DROP|x|` )    " unknown OPTION
      ( `TABNAME|I|BT|x|` )      " BT without HIGH
      ( `TABNAME|E|NB|x|` )      " NB without HIGH
      ( `TABNAME|I|EQ|x|y` )     " EQ with HIGH
      ( `TABNAME|I|CP|x*|y` )    " CP with HIGH
      ( `TABNAME|I|EQ|x` )       " 4 fields
      ( `TABNAME|I|EQ|x|y|z` ) ) " 6 fields
      .
    LOOP AT lt_bad INTO DATA(lv_bad).
      TRY.
          lcl_b5_predicate=>to_where( lcl_b5_predicate=>decode( VALUE #( ( lv_bad ) ) ) ).
          cl_abap_unit_assert=>fail( msg = |predicate [{ lv_bad }] was accepted| ).
        CATCH lcx_b5 INTO DATA(lx).
          cl_abap_unit_assert=>assert_equals( act = lx->code exp = `INVALID_PREDICATE` msg = lv_bad ).
      ENDTRY.
    ENDLOOP.
  ENDMETHOD.

  METHOD where_escapes_quotes.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_predicate=>to_where( VALUE #( ( fieldname = `TABNAME` sign = `I` option = `EQ` low = `O'BRIEN` )
                                                 ( fieldname = `FIELDNAME` sign = `I` option = `NE` low = `` ) ) )
      exp = `TABNAME = 'O''BRIEN' AND FIELDNAME <> ' '` ).
  ENDMETHOD.

  METHOD predicate_value_with_pipe.
    DATA(lt_preds) = lcl_b5_predicate=>decode( VALUE #(
      ( lcl_plaidcl_codec=>encode_row( VALUE #( ( `name` ) ( `eq` ) ( `A|B\C` ) ) ) )
      ( lcl_plaidcl_codec=>encode_row( VALUE #( ( `name` ) ( `e` ) ( `bt` ) ( `A|B` ) ( `C\D` ) ) ) ) ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_preds
      exp = VALUE ty_b5_predicates( ( fieldname = `NAME` option = `EQ` low = `A|B\C` )
                                    ( fieldname = `NAME` sign = `E` option = `BT` low = `A|B` high = `C\D` ) ) ).
    " Legacy rows on one field stay ANDed (a range); 5-field includes are ORed.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_predicate=>to_where( lcl_b5_predicate=>decode( VALUE #(
              ( `TABNAME|GE|DD0` ) ( `TABNAME|LT|DD1` ) ( `TABNAME|I|EQ|X1|` ) ( `TABNAME|I|EQ|X2|` ) ) ) )
      exp = `TABNAME >= 'DD0' AND TABNAME < 'DD1' AND ( TABNAME = 'X1' OR TABNAME = 'X2' )` ).
  ENDMETHOD.

  METHOD token_round_trips_hard_values.
    DATA(lt_keys) = VALUE string_table( ( `NAME` ) ( `NUMB` ) ( `TYPE` ) ).
    DATA(lt_values) = VALUE string_table( ( |A\|B\\C\nD\r\t| ) ( `0001` ) ( `` ) ).
    DATA(lv_token) = lcl_b5_keyset=>encode_token( iv_table = `TVARVC` it_keys = lt_keys
                                                  iv_fingerprint = `FP` it_values = lt_values ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_keyset=>decode_token( iv_token = lv_token iv_table = `TVARVC`
                                         it_keys = lt_keys iv_fingerprint = `FP` )
      exp = lt_values ).
  ENDMETHOD.

  METHOD token_refuses_swapped_keys.
    DATA(lv_token) = lcl_b5_keyset=>encode_token(
      iv_table = `DD03L` it_keys = VALUE #( ( `TABNAME` ) ( `FIELDNAME` ) )
      iv_fingerprint = `FP` it_values = VALUE #( ( `DD02L` ) ( `AS4DATE` ) ) ).
    expect_refusal( iv_token = lv_token iv_table = `DD03L`
                    it_keys = VALUE #( ( `FIELDNAME` ) ( `TABNAME` ) ) iv_fp = `FP` ).
  ENDMETHOD.

  METHOD token_refuses_other_fprint.
    DATA(lt_keys) = VALUE string_table( ( `TABNAME` ) ).
    DATA(lv_token) = lcl_b5_keyset=>encode_token( iv_table = `DD02L` it_keys = lt_keys
                                                  iv_fingerprint = `FP1` it_values = VALUE #( ( `X` ) ) ).
    expect_refusal( iv_token = lv_token iv_table = `DD02L` it_keys = lt_keys iv_fp = `FP2` ).
  ENDMETHOD.

  METHOD token_refuses_other_table.
    DATA(lt_keys) = VALUE string_table( ( `TABNAME` ) ).
    DATA(lv_token) = lcl_b5_keyset=>encode_token( iv_table = `DD02L` it_keys = lt_keys
                                                  iv_fingerprint = `FP` it_values = VALUE #( ( `X` ) ) ).
    expect_refusal( iv_token = lv_token iv_table = `DD03L` it_keys = lt_keys iv_fp = `FP` ).
  ENDMETHOD.

  METHOD token_refuses_garbage.
    expect_refusal( iv_token = `not-a-real-token` iv_table = `DD02L`
                    it_keys = VALUE #( ( `TABNAME` ) ) iv_fp = `FP` ).
  ENDMETHOD.

  METHOD token_refuses_other_client.
    " One client exists on A4H: edit the client/system part of a real token.
    DATA(lt_keys) = VALUE string_table( ( `TABNAME` ) ).
    DATA(lv_token) = lcl_b5_keyset=>encode_token( iv_table = `DD02L` it_keys = lt_keys
                                                  iv_fingerprint = `FP` it_values = VALUE #( ( `X` ) ) ).
    DATA(lt_parts) = lcl_plaidcl_codec=>decode_token( lv_token ).
    cl_abap_unit_assert=>assert_equals( act = lt_parts[ 2 ] exp = |{ sy-mandt }| msg = 'token client part' ).
    cl_abap_unit_assert=>assert_equals( act = lt_parts[ 3 ] exp = |{ sy-sysid }| msg = 'token system part' ).

    DATA(lt_client) = lt_parts.
    DATA(lv_client) = COND string( WHEN sy-mandt = '999' THEN `998` ELSE `999` ).
    MODIFY lt_client FROM lv_client INDEX 2.
    expect_refusal( iv_token = lcl_plaidcl_codec=>encode_token( lt_client )
                    iv_table = `DD02L` it_keys = lt_keys iv_fp = `FP` ).

    DATA(lt_system) = lt_parts.
    DATA(lv_system) = COND string( WHEN sy-sysid = 'ZZZ' THEN `ZZY` ELSE `ZZZ` ).
    MODIFY lt_system FROM lv_system INDEX 3.
    expect_refusal( iv_token = lcl_plaidcl_codec=>encode_token( lt_system )
                    iv_table = `DD02L` it_keys = lt_keys iv_fp = `FP` ).
  ENDMETHOD.

  METHOD token_is_jsonb_safe.
    " The platform stores the token in a JSONB column, which rejects only
    " U+0000. U+0001..U+001F other than TAB/LF/CR pass the codec
    " unescaped, so the token is JSONB-safe, not printable.
    DATA(lv_nul) = |{ cl_abap_char_utilities=>minchar }|.
    DATA(lt_keys) = VALUE string_table( ( `NAME` ) ( `TYPE` ) ).
    DATA(lt_values) = VALUE string_table(
      ( |A{ lv_nul }B\nC{ cl_abap_conv_in_ce=>uccp( '0001' ) }\t\r| ) ( `` ) ).
    DATA(lv_token) = lcl_b5_keyset=>encode_token( iv_table = `TVARVC` it_keys = lt_keys
                                                  iv_fingerprint = `FP` it_values = lt_values ).

    DATA(lv_len) = strlen( lv_token ).
    DO lv_len TIMES.
      DATA(lv_at) = sy-index - 1.
      cl_abap_unit_assert=>assert_differs(
        act = substring( val = lv_token off = lv_at len = 1 ) exp = lv_nul
        msg = |token has U+0000 at offset { lv_at }| ).
    ENDDO.
    cl_abap_unit_assert=>assert_not_initial( act = lcl_plaidcl_codec=>decode_token( lv_token )
                                             msg = 'token does not decode' ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_keyset=>decode_token( iv_token = lv_token iv_table = `TVARVC`
                                         it_keys = lt_keys iv_fingerprint = `FP` )
      exp = lt_values msg = 'token values do not round-trip' ).
  ENDMETHOD.

  METHOD fingerprint_tracks_inputs.
    DATA(lt_fields) = VALUE string_table( ( `NAME` ) ( `LOW` ) ).
    DATA(lt_preds) = VALUE string_table( ( `NAME|GE|Z` ) ).
    DATA(lv_base) = lcl_b5_keyset=>fingerprint( it_fields = lt_fields it_preds = lt_preds ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_keyset=>fingerprint( it_fields = lt_fields it_preds = lt_preds ) exp = lv_base ).
    cl_abap_unit_assert=>assert_differs(
      act = lcl_b5_keyset=>fingerprint( it_fields = VALUE #( ( `NAME` ) ) it_preds = lt_preds )
      exp = lv_base msg = 'changed IT_FIELDS kept the fingerprint' ).
    cl_abap_unit_assert=>assert_differs(
      act = lcl_b5_keyset=>fingerprint( it_fields = lt_fields
                                        it_preds = VALUE #( ( `NAME|GE|Y` ) ) )
      exp = lv_base msg = 'changed IT_PREDICATES kept the fingerprint' ).
  ENDMETHOD.

  METHOD terms_composite_key.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_keyset=>build_terms( it_keys   = VALUE #( ( `TABNAME` ) ( `FIELDNAME` ) )
                                        it_values = VALUE #( ( `DD02L` ) ( `` ) ) )
      exp = VALUE string_table( ( `TABNAME > 'DD02L'` )
                                ( `TABNAME = 'DD02L' AND FIELDNAME > ' '` ) ) ).
  ENDMETHOD.

  METHOD negative_packed_leading_minus.
    DATA lv_amount TYPE p LENGTH 8 DECIMALS 2 VALUE '-1000.00'.
    DATA lv_count TYPE i VALUE -5.
    DATA lv_text TYPE c LENGTH 10 VALUE 'ABC-'.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_reader=>to_text( iv_value = lv_amount iv_numeric = abap_true ) exp = `-1000.00` ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_reader=>to_text( iv_value = lv_count iv_numeric = abap_true ) exp = `-5` ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_reader=>to_text( iv_value = lv_text iv_numeric = abap_false ) exp = `ABC-` ).
  ENDMETHOD.

  METHOD keys_exact_any_order.
    lcl_b5_metadata=>check_keys( it_keys = VALUE #( ( `WERKS` ) ( `MATNR` ) ) it_cols = client_table( )
                                 iv_clidep = abap_true iv_table = `ZT` ).
  ENDMETHOD.

  METHOD keys_refuse_superset.
    " The D1 case: ERDAT, a nullable non-key column, would drop NULL rows.
    expect_key_refusal( it_keys = VALUE #( ( `ERDAT` ) ( `MATNR` ) ( `WERKS` ) ) it_cols = client_table( )
                        iv_code = `INVALID_KEY_FIELDS` iv_text = `*Missing:.*Extra: ERDAT*` ).
  ENDMETHOD.

  METHOD keys_refuse_missing.
    expect_key_refusal( it_keys = VALUE #( ( `ERDAT` ) ( `MATNR` ) ) it_cols = client_table( )
                        iv_code = `KEY_NOT_UNIQUE` iv_text = `*Missing: WERKS*Extra: ERDAT*` ).
  ENDMETHOD.

  METHOD keys_refuse_client_column.
    expect_key_refusal( it_keys = VALUE #( ( `MANDT` ) ( `MATNR` ) ( `WERKS` ) ) it_cols = client_table( )
                        iv_code = `INVALID_KEY_FIELDS` iv_text = `*MANDT*CLNT*` ).
  ENDMETHOD.

  METHOD keys_refuse_other_clnt.
    " Client-independent table: its CLNT key column is data, not the logon
    " client, and cannot be told apart from it.
    expect_key_refusal( it_keys = VALUE #( ( `MATNR` ) ( `WERKS` ) ) it_cols = client_table( )
                        iv_clidep = abap_false iv_code = `INVALID_KEY_FIELDS` iv_text = `*MANDT is CLNT*` ).
  ENDMETHOD.

  METHOD identifier_namespace_syntax.
    LOOP AT VALUE string_table( ( `FIELD` ) ( `/PLAIDCL/FIELD` ) ( `/1BCDWB/F_1` ) ) INTO DATA(lv_ok).
      lcl_b5_sql=>check_identifier( iv_name = lv_ok iv_code = `INVALID_FIELD` iv_allow_ns = abap_true ).
    ENDLOOP.
    LOOP AT VALUE string_table( ( `/NS/` ) ( `NS/FIELD` ) ( `/NS//FIELD` ) ( `/NS/FIELD/X` ) ( `//FIELD` )
                                ( `/NS/FIELD; DROP` ) ( `/N S/FIELD` ) ( `/NS/1FIELD` ) ( |FIELD\n| ) ) INTO DATA(lv_bad).
      TRY.
          lcl_b5_sql=>check_identifier( iv_name = lv_bad iv_code = `INVALID_FIELD` iv_allow_ns = abap_true ).
          cl_abap_unit_assert=>fail( msg = |identifier [{ lv_bad }] was accepted| ).
        CATCH lcx_b5 INTO DATA(lx).
          cl_abap_unit_assert=>assert_equals( act = lx->code exp = `INVALID_FIELD` ).
      ENDTRY.
    ENDLOOP.
  ENDMETHOD.

  METHOD identifier_length_limit.
    DATA(lv_30)   = repeat( val = `A` occ = 30 ).
    DATA(lv_ns30) = |/PLAIDCL/{ repeat( val = `A` occ = 21 ) }|.
    lcl_b5_sql=>check_identifier( iv_name = lv_30 iv_code = `INVALID_FIELD` ).
    lcl_b5_sql=>check_identifier( iv_name = lv_30 iv_code = `INVALID_FIELD` iv_allow_ns = abap_true ).
    lcl_b5_sql=>check_identifier( iv_name = lv_ns30 iv_code = `INVALID_FIELD` iv_allow_ns = abap_true ).

    LOOP AT VALUE string_table( ( |{ lv_30 }A| ) ( |{ lv_ns30 }A| ) ) INTO DATA(lv_long).
      DO 2 TIMES.
        DATA(lv_ns) = xsdbool( sy-index = 2 ).
        TRY.
            lcl_b5_sql=>check_identifier( iv_name = lv_long iv_code = `INVALID_FIELD` iv_allow_ns = lv_ns ).
            cl_abap_unit_assert=>fail( msg = |{ strlen( lv_long ) }-character [{ lv_long }] accepted, allow_ns [{ lv_ns }]| ).
          CATCH lcx_b5 INTO DATA(lx).
            cl_abap_unit_assert=>assert_equals( act = lx->code exp = `INVALID_FIELD` msg = lx->msg ).
        ENDTRY.
      ENDDO.
    ENDLOOP.
  ENDMETHOD.

  METHOD where_namespaced_field.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_predicate=>to_where( VALUE #( ( fieldname = `/PLAIDCL/F` sign = `I` option = `EQ` low = `x` ) ) )
      exp = `/PLAIDCL/F = 'x'` ).
  ENDMETHOD.

  METHOD where_select_options.
    " Includes of one field are ORed in parentheses, excludes ANDed as the
    " complementary option, fields ANDed in first-appearance order.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b5_predicate=>to_where( lcl_b5_predicate=>decode( VALUE #(
              ( `BUKRS|I|EQ|1000|` ) ( `GJAHR|I|GE|2020|` ) ( `BUKRS|I|EQ|2000|` )
              ( `BUKRS|E|BT|1500|1999` ) ( `NAME|E|CP|A*|` ) ) ) )
      exp = `( BUKRS = '1000' OR BUKRS = '2000' ) AND BUKRS NOT BETWEEN '1500' AND '1999' AND ` &&
            `GJAHR >= '2020' AND NAME NOT LIKE 'A%' ESCAPE '#'` ).
    DATA(lt_single) = VALUE string_table(
      ( `X|E|EQ|a|` ) ( `X|E|NE|a|` ) ( `X|E|GT|a|` ) ( `X|E|GE|a|` ) ( `X|E|LT|a|` ) ( `X|E|LE|a|` )
      ( `X|I|NB|a|b` ) ( `X|E|NB|a|b` ) ( `X|I|NP|a+|` ) ( `X|E|NP|a+|` ) ( `X|I|CP|O'B*|` ) ).
    DATA(lt_expected) = VALUE string_table(
      ( `X <> 'a'` ) ( `X = 'a'` ) ( `X <= 'a'` ) ( `X < 'a'` ) ( `X >= 'a'` ) ( `X > 'a'` )
      ( `X NOT BETWEEN 'a' AND 'b'` ) ( `X BETWEEN 'a' AND 'b'` )
      ( `X NOT LIKE 'a_' ESCAPE '#'` ) ( `X LIKE 'a_' ESCAPE '#'` ) ( `X LIKE 'O''B%' ESCAPE '#'` ) ).
    LOOP AT lt_single INTO DATA(lv_row).
      DATA(lv_index) = sy-tabix.
      cl_abap_unit_assert=>assert_equals(
        act = lcl_b5_predicate=>to_where( lcl_b5_predicate=>decode( VALUE #( ( lv_row ) ) ) )
        exp = lt_expected[ lv_index ]
        msg = lv_row ).
    ENDLOOP.
  ENDMETHOD.

  METHOD like_pattern_escapes.
    " SAP * + become % _; a literal % _ # is escaped with #; SAP's #x is x.
    cl_abap_unit_assert=>assert_equals( act = lcl_b5_predicate=>like_pattern( `50%_off*` ) exp = `50#%#_off%` ).
    cl_abap_unit_assert=>assert_equals( act = lcl_b5_predicate=>like_pattern( `a+#*b#+` ) exp = `a_*b+` ).
    cl_abap_unit_assert=>assert_equals( act = lcl_b5_predicate=>like_pattern( `#%#_##` ) exp = `#%#_##` ).
    cl_abap_unit_assert=>assert_equals( act = lcl_b5_predicate=>like_pattern( `x#` ) exp = `x##` ).
    cl_abap_unit_assert=>assert_equals( act = lcl_b5_predicate=>like_pattern( `a b` ) exp = `a b` ).
  ENDMETHOD.

  METHOD client_table.
    rt_cols = VALUE #( ( fieldname = 'MANDT' keyflag = 'X' datatype = 'CLNT' )
                       ( fieldname = 'MATNR' keyflag = 'X' datatype = 'CHAR' )
                       ( fieldname = 'WERKS' keyflag = 'X' datatype = 'CHAR' )
                       ( fieldname = 'ERDAT' keyflag = ' ' datatype = 'DATS' ) ).
  ENDMETHOD.

  METHOD expect_key_refusal.
    TRY.
        lcl_b5_metadata=>check_keys( it_keys = it_keys it_cols = it_cols iv_clidep = iv_clidep iv_table = `ZT` ).
        cl_abap_unit_assert=>fail( msg = |keys { concat_lines_of( table = it_keys sep = `,` ) } accepted| ).
      CATCH lcx_b5 INTO DATA(lx).
        cl_abap_unit_assert=>assert_equals( act = lx->code exp = iv_code msg = lx->msg ).
        cl_abap_unit_assert=>assert_char_cp( act = lx->msg exp = iv_text ).
    ENDTRY.
  ENDMETHOD.

  METHOD expect_refusal.
    TRY.
        lcl_b5_keyset=>decode_token( iv_token = iv_token iv_table = iv_table
                                     it_keys = it_keys iv_fingerprint = iv_fp ).
        cl_abap_unit_assert=>fail( msg = |token accepted for table { iv_table }| ).
      CATCH lcx_b5 INTO DATA(lx).
        cl_abap_unit_assert=>assert_equals( act = lx->code exp = `INVALID_CONT_STATE` ).
    ENDTRY.
  ENDMETHOD.

ENDCLASS.
