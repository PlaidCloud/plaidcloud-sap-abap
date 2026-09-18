*&---------------------------------------------------------------------*
*& sc-27793 (B4 -- Z_PLAIDCL_B4_CATALOG_TCODE, RFC).
*&---------------------------------------------------------------------*
* Resolves a tcode to its program, labels its write capability, and
* labels the B7 capture tier it would get. The source expansion, write
* scan and tier come from B7's shared engine (lcl_b7_tcode_capture in
* z_plaidcl_b7_run_tcode.abap) -- the exact code B7 runs before its
* SUBMIT, so this label cannot drift from that decision. Activate after
* B7.
*
* The write label is a label (plan §5), not a gate.
*
* HONESTY PROPERTIES:
*  - EV_WRITES_DETECTED and EV_INDETERMINATE are separate; both can be X.
*  - Unreadable source, or source whose includes could not all be
*    expanded, is EV_INDETERMINATE = X -- never "no writes".
*  - No program resolved: EV_SOURCE_READABLE = space, EV_INDETERMINATE =
*    X, EV_TIER_REFUSED = X.
*  - EV_RESOLVE_NOTE explains tcode resolution; EV_SCAN_NOTE explains the
*    write scan (names agreed with plaid PR #7882).
*
* WIRE: ET_FINDINGS rows are lcl_plaidcl_codec rows
*   LINE|STMT_TYPE|TARGET|CERTAINTY|SRC_LINE|INCLUDE
* Booleans cross RFC as 'X' / ' '; compare explicitly.
*&---------------------------------------------------------------------*

TYPES:
  BEGIN OF ty_b4_tcode_resolution,
    tcode        TYPE string,
    found        TYPE abap_bool,
    kind         TYPE string,   " DIALOG_TRANSACTION / REPORT_TRANSACTION / PARAMETER_TRANSACTION /
                                " OO_TRANSACTION_OR_UNRESOLVED / PARAMETER_TRANSACTION_CYCLE /
                                " PARAM_TCODE_HOP_LIMIT / NOT_FOUND
    program      TYPE programm,
    program_kind TYPE string,   " REPORT / NON_REPORT (subc=<x>) / UNKNOWN_NO_TRDIR_ENTRY
    via_tcode    TYPE tcode,
    raw_param    TYPE string,
    resolve_note TYPE string,
  END OF ty_b4_tcode_resolution.

CLASS lcl_b4_tcode_resolver DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS resolve
      IMPORTING pv_tcode         TYPE tcode
      RETURNING VALUE(rs_result) TYPE ty_b4_tcode_resolution.

  PRIVATE SECTION.
    CLASS-METHODS classify_program
      IMPORTING pv_program     TYPE programm
      RETURNING VALUE(rv_kind) TYPE string.

    CLASS-METHODS extract_target_tcode
      IMPORTING pv_param         TYPE string
      RETURNING VALUE(rv_target) TYPE tcode.
ENDCLASS.

CLASS lcl_b4_tcode_resolver IMPLEMENTATION.

  METHOD classify_program.
    DATA lv_subc TYPE trdir-subc.
    SELECT SINGLE subc FROM trdir INTO lv_subc WHERE name = pv_program.
    IF sy-subrc <> 0.
      rv_kind = 'UNKNOWN_NO_TRDIR_ENTRY'.
      RETURN.
    ENDIF.
    rv_kind = COND #(
      WHEN lv_subc = '1' THEN 'REPORT'
      ELSE |NON_REPORT (subc={ lv_subc })| ).
  ENDMETHOD.

  METHOD extract_target_tcode.
    " TSTCP-PARAM: first token is the target tcode (optionally '*'-prefixed
    " = skip initial screen), then optional field=value defaults. A first
    " token containing '=' is not a tcode and is reported unparseable.
    DATA(lv_param) = pv_param.
    CONDENSE lv_param.
    SHIFT lv_param LEFT DELETING LEADING '*'.
    SPLIT lv_param AT space INTO TABLE DATA(lt_tokens).
    IF lines( lt_tokens ) = 0.
      RETURN.
    ENDIF.
    DATA(lv_first) = lt_tokens[ 1 ].
    CONDENSE lv_first.
    IF lv_first IS INITIAL OR lv_first CA '='.
      RETURN.
    ENDIF.
    rv_target = lv_first.
  ENDMETHOD.

  METHOD resolve.
    DATA lv_current TYPE tcode.
    DATA lt_seen    TYPE STANDARD TABLE OF tcode.
    DATA ls_tstc    TYPE tstc.
    DATA lt_tstcp   TYPE STANDARD TABLE OF tstcp.

    rs_result-tcode = pv_tcode.
    lv_current = pv_tcode.

    DO 5 TIMES.
      IF line_exists( lt_seen[ table_line = lv_current ] ).
        rs_result-found        = abap_true.
        rs_result-kind         = 'PARAMETER_TRANSACTION_CYCLE'.
        rs_result-resolve_note = |cycle detected chasing parameter-transaction targets, stopped at [{ lv_current }]|.
        RETURN.
      ENDIF.
      APPEND lv_current TO lt_seen.

      SELECT SINGLE * FROM tstc INTO ls_tstc WHERE tcode = lv_current.
      IF sy-subrc <> 0.
        rs_result-found        = abap_false.
        rs_result-kind         = 'NOT_FOUND'.
        rs_result-resolve_note = |tcode [{ lv_current }] has no TSTC entry|.
        IF lv_current <> pv_tcode.
          rs_result-resolve_note = rs_result-resolve_note && | (chased here from [{ pv_tcode }] via TSTCP)|.
        ENDIF.
        RETURN.
      ENDIF.
      rs_result-found = abap_true.

      IF ls_tstc-pgmna IS NOT INITIAL.
        rs_result-program      = ls_tstc-pgmna.
        rs_result-program_kind = classify_program( ls_tstc-pgmna ).
        rs_result-kind = COND #( WHEN rs_result-program_kind = 'REPORT' THEN 'REPORT_TRANSACTION'
                                 ELSE 'DIALOG_TRANSACTION' ).
        IF lv_current <> pv_tcode.
          rs_result-via_tcode    = lv_current.
          rs_result-resolve_note = |resolved via parameter-transaction chase [{ pv_tcode }] -> [{ lv_current }]|.
        ENDIF.
        RETURN.
      ENDIF.

      SELECT * FROM tstcp INTO TABLE lt_tstcp WHERE tcode = lv_current.
      IF sy-subrc = 0 AND lines( lt_tstcp ) > 0.
        rs_result-raw_param = lt_tstcp[ 1 ]-param.
        rs_result-kind      = 'PARAMETER_TRANSACTION'.
        DATA(lv_target) = extract_target_tcode( CONV #( lt_tstcp[ 1 ]-param ) ).
        IF lv_target IS INITIAL.
          rs_result-resolve_note = |PARAM=[{ rs_result-raw_param }]: target tcode could not be parsed; | &&
                                   |no program returned rather than guessing one|.
          RETURN.
        ENDIF.
        lv_current = lv_target.
        CONTINUE.
      ENDIF.

      rs_result-kind         = 'OO_TRANSACTION_OR_UNRESOLVED'.
      rs_result-resolve_note = `TSTC-PGMNA is blank and no TSTCP row exists (OO or other dispatch); ` &&
                               `no program name is returned rather than guessing one.`.
      RETURN.
    ENDDO.

    rs_result-kind         = 'PARAM_TCODE_HOP_LIMIT'.
    rs_result-resolve_note = |gave up after 5 parameter-transaction hops, last tcode [{ lv_current }]|.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B4_CATALOG_TCODE -- remote-enabled, group Z_PLAIDCL.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b4_catalog_tcode.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_REPORT) TYPE  PROGRAMM OPTIONAL
*"  EXPORTING
*"     VALUE(EV_TCODE_FOUND) TYPE  BOOLE_D
*"     VALUE(EV_TCODE_KIND) TYPE  STRING
*"     VALUE(EV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(EV_PROGRAM_KIND) TYPE  STRING
*"     VALUE(EV_VIA_TCODE) TYPE  TCODE
*"     VALUE(EV_RAW_PARAM) TYPE  STRING
*"     VALUE(EV_RESOLVE_NOTE) TYPE  STRING
*"     VALUE(EV_SOURCE_READABLE) TYPE  BOOLE_D
*"     VALUE(EV_SOURCE_LINES_SEEN) TYPE  I
*"     VALUE(EV_INCLUDES_EXPANDED) TYPE  I
*"     VALUE(EV_WRITES_DETECTED) TYPE  BOOLE_D
*"     VALUE(EV_INDETERMINATE) TYPE  BOOLE_D
*"     VALUE(EV_SCAN_NOTE) TYPE  STRING
*"     VALUE(ET_FINDINGS) TYPE  STRING_TABLE
*"     VALUE(EV_TIER) TYPE  STRING
*"     VALUE(EV_TIER_LABEL) TYPE  STRING
*"     VALUE(EV_TIER_REFUSED) TYPE  BOOLE_D
*"     VALUE(EV_TIER_REFUSAL_REASON) TYPE  STRING
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_AUTHORIZED
*"----------------------------------------------------------------------



  DATA lv_v1      TYPE symsgv.
  DATA lv_v2      TYPE symsgv.
  DATA lv_v3      TYPE symsgv.
  DATA lv_v4      TYPE symsgv.
  DATA lv_program TYPE programm.
  DATA lv_subc    TYPE trdir-subc.

  CLEAR: ev_tcode_found, ev_tcode_kind, ev_program, ev_program_kind, ev_via_tcode,
         ev_raw_param, ev_resolve_note, ev_source_readable, ev_source_lines_seen,
         ev_includes_expanded, ev_writes_detected, ev_indeterminate, ev_scan_note,
         et_findings, ev_tier, ev_tier_label, ev_tier_refused, ev_tier_refusal_reason.

  IF ( iv_tcode IS INITIAL AND iv_report IS INITIAL )
     OR ( iv_tcode IS NOT INITIAL AND iv_report IS NOT INITIAL ).
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = `Supply exactly one of IV_TCODE / IV_REPORT.`
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  IF iv_report IS NOT INITIAL.
    lv_program      = iv_report.
    ev_program      = lv_program.
    ev_tcode_found  = abap_false.
    ev_tcode_kind   = 'NOT_APPLICABLE_DIRECT_PROGRAM'.
    ev_resolve_note = 'IV_REPORT supplied directly -- tcode resolution was not performed.'.
    SELECT SINGLE subc FROM trdir INTO lv_subc WHERE name = lv_program.
    ev_program_kind = COND #( WHEN sy-subrc <> 0 THEN 'UNKNOWN_NO_TRDIR_ENTRY'
                              WHEN lv_subc = '1' THEN 'REPORT'
                              ELSE |NON_REPORT (subc={ lv_subc })| ).
  ELSE.
    DATA(ls_resolve) = lcl_b4_tcode_resolver=>resolve( iv_tcode ).
    ev_tcode_found  = ls_resolve-found.
    ev_tcode_kind   = ls_resolve-kind.
    ev_program      = ls_resolve-program.
    ev_program_kind = ls_resolve-program_kind.
    ev_via_tcode    = ls_resolve-via_tcode.
    ev_raw_param    = ls_resolve-raw_param.
    ev_resolve_note = ls_resolve-resolve_note.
    lv_program      = ls_resolve-program.
  ENDIF.

  IF lv_program IS INITIAL.
    ev_source_readable     = abap_false.
    ev_indeterminate       = abap_true.
    ev_scan_note           = |No program resolved for tcode [{ iv_tcode }] (kind={ ev_tcode_kind }); | &&
                             |write capability is UNKNOWN, not "no writes found".|.
    ev_tier                = 'C'.
    ev_tier_label          = 'REFUSED'.
    ev_tier_refused        = abap_true.
    ev_tier_refusal_reason = |Refused: no program resolved for tcode [{ iv_tcode }] to classify.|.
    RETURN.
  ENDIF.

  DATA(ls_source) = lcl_b7_tcode_capture=>read_source( lv_program ).
  IF ls_source-denied = abap_true.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = ls_source-denied_reason
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
  ENDIF.

  DATA(ls_scan)        = lcl_b7_tcode_capture=>scan_writes( ls_source ).
  ev_source_readable   = ls_scan-source_readable.
  ev_source_lines_seen = ls_scan-source_lines_seen.
  ev_includes_expanded = ls_scan-includes_expanded.
  ev_writes_detected   = ls_scan-writes_detected.
  ev_indeterminate     = ls_scan-indeterminate.
  ev_scan_note         = ls_scan-scan_note.
  LOOP AT ls_scan-findings INTO DATA(ls_finding).
    APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
      ( |{ ls_finding-line }| ) ( |{ ls_finding-stmt_type }| ) ( |{ ls_finding-target }| )
      ( |{ ls_finding-certainty }| ) ( |{ ls_finding-src_line }| ) ( CONV string( ls_finding-incl ) ) ) ) TO et_findings.
  ENDLOOP.

  DATA(ls_tier)          = lcl_b7_tcode_capture=>classify_source( ls_source ).
  ev_tier                = ls_tier-tier.
  ev_tier_label          = ls_tier-tier_label.
  ev_tier_refused        = ls_tier-refused.
  ev_tier_refusal_reason = ls_tier-refusal_reason.

ENDFUNCTION.
