*&---------------------------------------------------------------------*
*& sc-27789 (B2 -- Z_PLAIDCL_B2_CATTABLE, RFC wrapper).
*&---------------------------------------------------------------------*
* Thin, remote-enabled FM wrapper around the AUnit-verified logic in
* z_plaidcl_b2_cattable.abap (REPORT, UNMODIFIED, still live). That
* REPORT's LCL_TABLE_CATALOG=>CLASSIFY_TABCLASS / CLASSIFY_TABLE are
* copied here VERBATIM (renamed under a b2 prefix for group-scope
* hygiene only -- no logic changed) so an FM body can call them and
* flatten the result onto the wire, batched over a caller-supplied list
* of table names (a single-table classify is just a one-element list).
*
* Deploys into the SAME Z_PLAIDCL function group as B1/B5/B6/B7/B8/B12.
* New names introduced here: LCL_B2_TABLE_CATALOG (class),
* TY_B2_CLASSIFICATION (type, body-scope-only use -- never an FM
* top-level parameter type, so this is safe to declare ahead of
* FUNCTION per the group's established convention).
*
* THE HONESTY PROPERTY THIS FILE MUST NOT FLATTEN AWAY: EV_CLASSIFY in
* every row is one of CURSOR_NATIVE / PRIMARY_KEY_ONLY / NOT_OFFERABLE,
* a plain string -- never coerced to a boolean "usable" flag. A table
* this scan cannot vouch for (unknown TABCLASS, a VIEW with no key
* field, POOL/CLUSTER, INTTAB, or a name with no DD02L entry at all)
* comes back NOT_OFFERABLE, and that string IS the answer; do not let a
* caller collapse it into "false" alongside PRIMARY_KEY_ONLY.
*
* WIRE CONTRACT:
*   - Every ABAP_BOOL field (EV_FOUND, EV_HAS_STATS) crosses RFC as
*     'X' / a single space, never blank -- compare explicitly
*     (`value == 'X'`), same caveat as every other Bn FM in this
*     package (a bare space is truthy Python).
*   - ET_RESULTS rows are CODEC rows (lcl_plaidcl_codec=>encode_row /
*     decode_row, Contract 2), exactly 6 fields in this fixed order:
*       "TABNAME|FOUND|TABCLASS|CLASSIFY|HAS_STATS|RANK_NOTE"
*     RANK_NOTE is free text -- it can embed a raw DD09L row fragment
*     (e.g. "DD09L present: LOIO|L") which may itself contain a pipe
*     or a backslash. A caller MUST decode with the codec, never a
*     plain `split('|')`: the codec escapes `\` and `|` (and LF/CR/TAB/
*     NUL) inside every field, including RANK_NOTE, so decoding always
*     recovers exactly 6 fields regardless of what RANK_NOTE contains.
*
* SCOPE: target is SAP_BASIS 816 ABAP Platform, no S4CORE. Classification
* reads only DD02L/DD03L/DD09L (DDIC catalog metadata) -- this is a
* statement about a table's STRUCTURE, never its ERP business content.
*&---------------------------------------------------------------------*

TYPES: BEGIN OF ty_b2_classification,
         tabname   TYPE string,
         found     TYPE abap_bool,
         tabclass  TYPE string,
         classify  TYPE string,   " CURSOR_NATIVE / PRIMARY_KEY_ONLY / NOT_OFFERABLE
         has_stats TYPE abap_bool,
         rank_note TYPE string,
       END OF ty_b2_classification.

CLASS lcl_b2_table_catalog DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_delimiter TYPE c LENGTH 1 VALUE '|'.

    " Per §3.1: classification is a pure function of DD02L-TABCLASS,
    " read live -- never a hardcoded table-name allowlist. Verbatim
    " copy of z_plaidcl_b2_cattable.abap's own LCL_TABLE_CATALOG=>
    " CLASSIFY_TABCLASS.
    CLASS-METHODS classify_tabclass
      IMPORTING pv_tabclass       TYPE string
                pv_has_key_field  TYPE abap_bool
      RETURNING VALUE(rv_class)   TYPE string.

    " Verbatim copy of the proven REPORT's CLASSIFY_TABLE, plus an
    " up-front FOUND flag so a caller can distinguish "no DD02L entry"
    " from every other outcome without parsing RANK_NOTE text.
    CLASS-METHODS classify_table
      IMPORTING pv_tabname       TYPE tabname
      RETURNING VALUE(rs_result) TYPE ty_b2_classification.

    " ORCHESTRATION + WIRE-BOUNDARY VALIDATION. Not part of the proven
    " REPORT (that program classified one hardcoded literal name at a
    " time) -- this is the new logic this FM wrapper adds, and it is
    " exactly the RFC entry-point boundary check CLASSIFY_TABLE itself
    " does not do (it embeds PV_TABNAME directly into a dynamic
    " RFC_READ_TABLE WHERE-option string with no escaping, which was
    " safe when every caller was a hardcoded AUnit literal and is NOT
    " safe once PV_TABNAME can be arbitrary caller input over RFC).
    " Every name is checked with B5's own LCL_SQL_SAFETY=>CHECK_IDENTIFIER
    " (already live in this same function group) BEFORE it ever reaches
    " CLASSIFY_TABLE; a name that fails never reaches the proven method
    " at all and is reported as a synthetic "(INVALID_NAME)" row instead.
    CLASS-METHODS classify_batch
      IMPORTING pt_tabnames    TYPE string_table
      RETURNING VALUE(rt_rows) TYPE string_table.
ENDCLASS.

CLASS lcl_b2_table_catalog IMPLEMENTATION.

  METHOD classify_tabclass.
    rv_class = COND string(
      WHEN pv_tabclass = 'TRANSP' THEN 'CURSOR_NATIVE'
      WHEN pv_tabclass = 'POOL'   THEN 'PRIMARY_KEY_ONLY'
      WHEN pv_tabclass = 'CLUSTER' THEN 'PRIMARY_KEY_ONLY'
      WHEN pv_tabclass = 'VIEW' AND pv_has_key_field = abap_true THEN 'CURSOR_NATIVE'
      WHEN pv_tabclass = 'VIEW' THEN 'NOT_OFFERABLE'
      WHEN pv_tabclass = 'INTTAB' THEN 'NOT_OFFERABLE'
      ELSE 'NOT_OFFERABLE' ).                      " unknown class: refuse, never guess
  ENDMETHOD.

  METHOD classify_table.
    rs_result-tabname = pv_tabname.

    " --- DD02L: TABCLASS, the per-release ground truth ---
    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.

    APPEND VALUE #( fieldname = 'TABCLASS' ) TO lt_fields.
    APPEND VALUE #( fieldname = 'CONTFLAG' ) TO lt_fields.
    APPEND VALUE #( text = |TABNAME = '{ pv_tabname }'| ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD02L' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    IF sy-subrc <> 0 OR lines( lt_data ) = 0.
      rs_result-found     = abap_false.
      rs_result-tabclass  = 'UNKNOWN'.
      rs_result-classify  = 'NOT_OFFERABLE'.
      rs_result-rank_note = 'no DD02L entry found'.
      RETURN.
    ENDIF.
    rs_result-found = abap_true.
    SPLIT lt_data[ 1 ]-wa AT '|' INTO TABLE DATA(lt_parts).
    rs_result-tabclass = COND #( WHEN lines( lt_parts ) >= 1 THEN lt_parts[ 1 ] ELSE '' ).
    CONDENSE rs_result-tabclass.

    " --- DD03L: does it have at least one key field? (needed for VIEW) ---
    CLEAR: lt_fields, lt_options, lt_data.
    APPEND VALUE #( fieldname = 'KEYFLAG' ) TO lt_fields.
    APPEND VALUE #( text = |TABNAME = '{ pv_tabname }' AND KEYFLAG = 'X'| ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD03L' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    DATA(lv_has_key) = xsdbool( sy-subrc = 0 AND lines( lt_data ) > 0 ).

    rs_result-classify = classify_tabclass(
      pv_tabclass      = rs_result-tabclass
      pv_has_key_field = lv_has_key ).

    " --- DD09L: storage/runtime statistics, used for ranking. Absent
    " for a table that was never analyzed (typical for a brand-new
    " Z-table) -- honest fallback, never guessed. ---
    CLEAR: lt_fields, lt_options, lt_data.
    APPEND VALUE #( fieldname = 'TABART' )   TO lt_fields.
    APPEND VALUE #( fieldname = 'CONTFLAG' ) TO lt_fields.
    APPEND VALUE #( text = |TABNAME = '{ pv_tabname }'| ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD09L' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    IF sy-subrc = 0 AND lines( lt_data ) > 0.
      rs_result-has_stats = abap_true.
      rs_result-rank_note = |DD09L present: { lt_data[ 1 ]-wa }|.
    ELSE.
      rs_result-has_stats = abap_false.
      rs_result-rank_note = 'STALE_NO_DD09L_FALLBACK: no storage stats -- ranked as unknown-size, ' &&
                             'treated as small/low-priority rather than guessed.'.
    ENDIF.
  ENDMETHOD.

  METHOD classify_batch.
    LOOP AT pt_tabnames INTO DATA(lv_tab).
      DATA(lv_valid) = abap_true.
      TRY.
          lcl_b5_sql=>check_identifier( iv_name = lv_tab iv_code = `INVALID_NAME` iv_allow_ns = abap_true ).
        CATCH lcx_b5.
          lv_valid = abap_false.
      ENDTRY.

      IF lv_valid = abap_false.
        APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
          ( `(INVALID_NAME)` )
          ( CONV string( abap_false ) )
          ( `UNKNOWN` )
          ( `NOT_OFFERABLE` )
          ( CONV string( abap_false ) )
          ( |Rejected identifier [{ lv_tab }]: not a valid ABAP/DDIC name| ) ) ) TO rt_rows.
        CONTINUE.
      ENDIF.

      DATA(ls_result) = classify_table( CONV #( to_upper( lv_tab ) ) ).
      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ ls_result-tabname }| )
        ( CONV string( ls_result-found ) )
        ( |{ ls_result-tabclass }| )
        ( |{ ls_result-classify }| )
        ( CONV string( ls_result-has_stats ) )
        ( |{ ls_result-rank_note }| ) ) ) TO rt_rows.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& THE FUNCTION MODULE ITSELF.
*&
*& Remote-enabled (RFC). Deploys as Z_PLAIDCL_B2_CATTABLE inside the
*& live Z_PLAIDCL function group. Signature is INLINE between the
*& FUNCTION name and the terminating period -- see z_plaidcl_ping.abap
*& for why the classic *" Local Interface: block is forbidden here.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b2_cattable.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IT_TABNAMES) TYPE  STRING_TABLE
*"  EXPORTING
*"     VALUE(EV_DELIMITER) TYPE  STRING
*"     VALUE(EV_RESULT_COUNT) TYPE  I
*"     VALUE(ET_RESULTS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"----------------------------------------------------------------------



  CLEAR: ev_delimiter, ev_result_count, et_results.

  IF it_tabnames IS INITIAL.
    MESSAGE e001(00) WITH 'IT_TABNAMES must not be empty' RAISING invalid_input.
  ENDIF.

  ev_delimiter = lcl_b2_table_catalog=>c_delimiter.
  et_results   = lcl_b2_table_catalog=>classify_batch( it_tabnames ).
  ev_result_count = lines( et_results ).

ENDFUNCTION.

*&---------------------------------------------------------------------*
*& D2 codec regression: RANK_NOTE is free text and can itself contain a
*& pipe or backslash (a real DD09L row fragment can, e.g. "LOIO|L").
*& The pre-fix code built ET_RESULTS with a raw pipe join, which would
*& over-split on exactly this input; the codec must not. Local class
*& logic only -- no RFC, no DB write, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b2fm_codec DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS rank_note_pipe_bslash_rtrip FOR TESTING.
ENDCLASS.

CLASS ltcl_b2fm_codec IMPLEMENTATION.
  METHOD rank_note_pipe_bslash_rtrip.
    DATA(ls_result) = VALUE ty_b2_classification(
      tabname   = 'ZTEST'
      found     = abap_true
      tabclass  = 'TRANSP'
      classify  = 'CURSOR_NATIVE'
      has_stats = abap_true
      rank_note = `DD09L present: LOIO|L, path C:\temp\x` ).

    DATA(lv_row) = lcl_plaidcl_codec=>encode_row( VALUE string_table(
      ( |{ ls_result-tabname }| )
      ( CONV string( ls_result-found ) )
      ( |{ ls_result-tabclass }| )
      ( |{ ls_result-classify }| )
      ( CONV string( ls_result-has_stats ) )
      ( |{ ls_result-rank_note }| ) ) ).
    DATA(lt_decoded) = lcl_plaidcl_codec=>decode_row( lv_row ).

    cl_abap_unit_assert=>assert_equals( act = lines( lt_decoded ) exp = 6
      msg = |field count must stay 6 despite embedded \| and \\ in RANK_NOTE: [{ lv_row }]| ).
    cl_abap_unit_assert=>assert_equals( act = lt_decoded[ 6 ] exp = ls_result-rank_note
      msg = |RANK_NOTE must round-trip exactly, pipe and backslash included: [{ lv_row }]| ).
    cl_abap_unit_assert=>assert_equals( act = lt_decoded[ 1 ] exp = ls_result-tabname
      msg = |TABNAME must not have absorbed part of RANK_NOTE: [{ lv_row }]| ).
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& VERIFICATION CHECKLIST (mechanical pass once the system is usable).
*& NOT activated or run this session -- see z_plaidcl_b1_capabilities_
*& fm.abap's own checklist header for why (trial pod never finished
*& booting). Static-only pass done, nothing executed on a kernel.
*&
*& Deploy:
*&   source scripts/adt.sh; adt_init
*&   adt_deploy_fm Z_PLAIDCL Z_PLAIDCL_B2_CATTABLE \
*&     src/z_plaidcl_b2_cattable_fm.abap "B2 table catalog/classify (RFC)"
*&   Confirm put=200 AND activationExecuted="true" with ZERO messages.
*&
*& 1. Call with IT_TABNAMES = ( 'DD02L' 'TSTC' ). EXPECT: two rows, both
*&    "TABNAME|X|TRANSP|CURSOR_NATIVE|<has_stats>|<rank_note>" (both are
*&    TRANSP tables that exist on every Basis system; RANK_NOTE is
*&    either "DD09L present: ..." or the STALE_NO_DD09L_FALLBACK text,
*&    read live rather than assumed).
*& 2. Call with IT_TABNAMES = ( 'ZZZPLAIDCLNOPE_TABLE' ). EXPECT: one
*&    row "ZZZPLAIDCLNOPE_TABLE|<space>|UNKNOWN|NOT_OFFERABLE|<space>|
*&    no DD02L entry found" -- a normal negative result, no exception.
*& 3. Call with IT_TABNAMES = ( `DD02L' OR '1'='1` ) (an injection-
*&    shaped name). EXPECT: a row "(INVALID_NAME)|<space>|UNKNOWN|
*&    NOT_OFFERABLE|<space>|Rejected identifier [...]" -- rejected by
*&    LCL_SQL_SAFETY=>CHECK_IDENTIFIER before CLASSIFY_TABLE ever runs.
*& 4. Call with IT_TABNAMES empty. EXPECT: EXCEPTION INVALID_INPUT, no
*&    RFC_READ_TABLE call made.
*& 5. If a real POOL/CLUSTER table can be found live (same discovery
*&    the REPORT's own ltcl_b2=>d_classify_pool_or_cluster does), add it
*&    to IT_TABNAMES and confirm CLASSIFY = PRIMARY_KEY_ONLY -- exercises
*&    the one CLASSIFY value this checklist's other cases don't reach.
*& 6. Group-level activation check: confirm B1/B5/B6/B7/B8/B12 (GET 200
*&    on each) are unchanged after this FM lands in the same unit.
*&
*& NOT verifiable on this SAP_BASIS 816, no-S4CORE trial system: every
*& classification is a statement about a table's DDIC STRUCTURE
*& (DD02L/DD03L/DD09L), never its ERP business content -- same scope
*& note as the REPORT this file wraps.
*&---------------------------------------------------------------------*
