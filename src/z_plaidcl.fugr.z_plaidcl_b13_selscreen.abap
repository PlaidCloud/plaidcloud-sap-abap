*&---------------------------------------------------------------------*
*& B13 -- Z_PLAIDCL_B13_SELSCREEN, selection-screen descriptor (RFC).
*& Epic 27751 Track B; unblocks D4 (sc-27762) and D5 (sc-27765).
*&---------------------------------------------------------------------*
* MECHANISM: source scan, not RS_SELECTIONSCREEN_READ. A screen-
* introspection FM plausibly walks a live dynpro, which risks the
* uncatchable DYNPRO_SEND_IN_BACKGROUND abort; READ REPORT is a plain
* data read. Source expansion (transitive INCLUDEs, namespaced names,
* cycle guard, cap), comment stripping, statement splitting and the
* PARAMETERS / SELECT-OPTIONS parse are B7's shared engine
* (lcl_b7_tcode_capture), the same parse B7's selection-coverage gate
* uses. Activate after B7. This FM adds the per-field detail D4/D5 need:
* KIND, OBLIGATORY, DEFAULT and a DDIC data element where resolvable.
*
* DDIC_STATUS:
*   RESOLVED      -- a DD04L data element (TYPE, or LIKE/FOR table-field).
*   NO_DDIC_TYPE  -- a builtin elementary type or a same-program TYPES.
*   INDETERMINATE -- the scan cannot tell (local variable, unknown name).
* INDETERMINATE is never coerced to either of the others.
*
* EV_SOURCE_COMPLETE = space means an include could not be read or
* expanded (dynamic, unreadable, cap); the field list may be missing
* fields. It is reported, not hidden.
*
* KNOWN LIMITS: LIKE/FOR x-y resolves only when x is an active DD02L
* object; a structured local TYPES can fall through to INDETERMINATE.
*
* WIRE: ET_FIELDS rows are lcl_plaidcl_codec rows
*   FIELDNAME|KIND|OBLIGATORY|DDIC_STATUS|ROLLNAME|DEFAULT_VALUE|NOTE
* OBLIGATORY is 'X' or empty. EV_FIELD_COUNT is authoritative. A program
* with no selection screen returns EV_FOUND = space, no exception.
* Errors are MESSAGE e001(00) ... RAISING (Contract 3).
*&---------------------------------------------------------------------*

TYPES:
  BEGIN OF ty_b13_field,
    fieldname     TYPE string,
    kind          TYPE string,
    obligatory    TYPE abap_bool,
    ddic_status   TYPE string,
    rollname      TYPE string,
    default_value TYPE string,
    note          TYPE string,
  END OF ty_b13_field.
TYPES ty_b13_fields TYPE STANDARD TABLE OF ty_b13_field WITH DEFAULT KEY.

CLASS lcl_b13_selscreen DEFINITION FINAL.
  PUBLIC SECTION.
    CLASS-METHODS scan_fields
      IMPORTING pv_program          TYPE programm
      EXPORTING et_fields           TYPE ty_b13_fields
                ev_source_readable  TYPE abap_bool
                ev_source_complete  TYPE abap_bool
                ev_includes_scanned TYPE i
                ev_denied           TYPE abap_bool
                ev_denied_reason    TYPE string.

  PRIVATE SECTION.
    " RR2: FIND REGEX wrapped so a pathological clause degrades to "no
    " match" (the same outcome an ordinary non-match already produces)
    " instead of an uncaught CX_SY_REGEX_TOO_COMPLEX dump.
    CLASS-METHODS try_find_regex
      IMPORTING pv_pattern   TYPE string
                pv_text      TYPE string
      EXPORTING ev_matched   TYPE abap_bool
                ev_submatch  TYPE string.

    CLASS-METHODS parse_field
      IMPORTING ps_selfield     TYPE ty_b7_selfield
                pv_full_source  TYPE string
      RETURNING VALUE(rs_field) TYPE ty_b13_field.

    CLASS-METHODS resolve_type_ref
      IMPORTING pv_kind        TYPE string
                pv_ref         TYPE string
                pv_ref_kw      TYPE string
                pv_had_ref     TYPE abap_bool
                pv_full_source TYPE string
      EXPORTING ev_status      TYPE string
                ev_rollname    TYPE string
                ev_note        TYPE string.

    CLASS-METHODS is_builtin_type
      IMPORTING pv_name       TYPE string
      RETURNING VALUE(rv_yes) TYPE abap_bool.

    CLASS-METHODS has_local_type
      IMPORTING pv_name        TYPE string
                pv_full_source TYPE string
      RETURNING VALUE(rv_yes)  TYPE abap_bool.
ENDCLASS.

CLASS lcl_b13_selscreen IMPLEMENTATION.

  METHOD try_find_regex.
    CLEAR: ev_matched, ev_submatch.
    TRY.
        FIND REGEX pv_pattern IN pv_text IGNORING CASE SUBMATCHES ev_submatch.
        ev_matched = xsdbool( sy-subrc = 0 ).
      CATCH cx_sy_regex_too_complex.
        ev_matched = abap_false.
    ENDTRY.
  ENDMETHOD.

  METHOD scan_fields.
    DATA lv_flat  TYPE string.
    DATA lt_flat  TYPE string_table.
    DATA ls_field TYPE ty_b13_field.

    CLEAR et_fields.
    DATA(ls_source) = lcl_b7_tcode_capture=>read_source( pv_program ).
    ev_source_readable  = ls_source-readable.
    ev_source_complete  = ls_source-complete.
    ev_includes_scanned = ls_source-includes_expanded.
    ev_denied           = ls_source-denied.
    ev_denied_reason    = ls_source-denied_reason.
    IF ls_source-readable = abap_false.
      RETURN.
    ENDIF.

    DATA lt_stmts     TYPE ty_b7_stmts.
    DATA lt_selfields TYPE ty_b7_selfields.
    " RR2: the classifier's regexes can raise on pathological source. The scan
    " then reports an incomplete source with no fields instead of dumping.
    TRY.
        lt_stmts = lcl_b7_tcode_capture=>statements( ls_source ).
        lt_selfields = lcl_b7_tcode_capture=>selection_fields( lt_stmts ).
      CATCH cx_sy_regex_too_complex cx_sy_no_handler.
        ev_source_complete = abap_false.
        RETURN.
    ENDTRY.
    " Build the flat source once (append + join). A per-statement template
    " over ~300 includes was O(n^2) rebuilds of the whole string.
    LOOP AT lt_stmts INTO DATA(ls_stmt).
      APPEND |{ ls_stmt-code }.| TO lt_flat.
    ENDLOOP.
    lv_flat = concat_lines_of( table = lt_flat ).

    LOOP AT lt_selfields INTO DATA(ls_selfield).
      ls_field = parse_field( ps_selfield = ls_selfield pv_full_source = lv_flat ).
      APPEND ls_field TO et_fields.
    ENDLOOP.
  ENDMETHOD.

  METHOD parse_field.
    DATA lv_def     TYPE string.
    DATA lv_ref     TYPE string.
    DATA lv_ref_kw  TYPE string.
    DATA lv_had_ref TYPE abap_bool.
    DATA lv_matched TYPE abap_bool.

    rs_field-fieldname  = ps_selfield-name.
    rs_field-kind       = COND #( WHEN ps_selfield-kind = 'P' THEN `PARAMETER` ELSE `SELECT-OPTION` ).
    rs_field-obligatory = ps_selfield-obligatory.
    DATA(lv_clause) = ps_selfield-clause.

    try_find_regex( EXPORTING pv_pattern = `DEFAULT\s+'(([^']|'')*)'` pv_text = lv_clause
                    IMPORTING ev_matched = lv_matched ev_submatch = lv_def ).
    IF lv_matched = abap_true.
      REPLACE ALL OCCURRENCES OF `''` IN lv_def WITH `'`.
      rs_field-default_value = lv_def.
    ELSE.
      try_find_regex( EXPORTING pv_pattern = `DEFAULT\s+(\S+)` pv_text = lv_clause
                      IMPORTING ev_matched = lv_matched ev_submatch = lv_def ).
      IF lv_matched = abap_true.
        rs_field-default_value = lv_def.
      ENDIF.
    ENDIF.

    IF ps_selfield-kind = 'S'.
      try_find_regex( EXPORTING pv_pattern = `FOR\s+([\w/~-]+)` pv_text = lv_clause
                      IMPORTING ev_matched = lv_matched ev_submatch = lv_ref ).
      IF lv_matched = abap_true.
        lv_ref_kw  = 'FOR'.
        lv_had_ref = abap_true.
      ENDIF.
    ELSE.
      try_find_regex( EXPORTING pv_pattern = `TYPE\s+([\w/~]+)` pv_text = lv_clause
                      IMPORTING ev_matched = lv_matched ev_submatch = lv_ref ).
      IF lv_matched = abap_true.
        lv_ref_kw  = 'TYPE'.
        lv_had_ref = abap_true.
      ELSE.
        try_find_regex( EXPORTING pv_pattern = `LIKE\s+([\w/~-]+)` pv_text = lv_clause
                        IMPORTING ev_matched = lv_matched ev_submatch = lv_ref ).
        IF lv_matched = abap_true.
          lv_ref_kw  = 'LIKE'.
          lv_had_ref = abap_true.
        ENDIF.
      ENDIF.
    ENDIF.

    resolve_type_ref(
      EXPORTING pv_kind        = rs_field-kind
                pv_ref         = lv_ref
                pv_ref_kw      = lv_ref_kw
                pv_had_ref     = lv_had_ref
                pv_full_source = pv_full_source
      IMPORTING ev_status      = rs_field-ddic_status
                ev_rollname    = rs_field-rollname
                ev_note        = rs_field-note ).
  ENDMETHOD.

  METHOD is_builtin_type.
    " ABAP_BOOL is deliberately absent: it is a real DD04L data element.
    DATA(lv_name) = to_upper( pv_name ).
    rv_yes = xsdbool(
      lv_name = 'C'  OR lv_name = 'N'    OR lv_name = 'I'    OR lv_name = 'P'  OR
      lv_name = 'D'  OR lv_name = 'T'    OR lv_name = 'X'    OR lv_name = 'F'  OR
      lv_name = 'B'  OR lv_name = 'S'    OR
      lv_name = 'STRING'     OR lv_name = 'XSTRING'    OR
      lv_name = 'DECFLOAT16' OR lv_name = 'DECFLOAT34' OR
      lv_name = 'INT1' OR lv_name = 'INT2' OR lv_name = 'INT4' OR lv_name = 'INT8' ).
  ENDMETHOD.

  METHOD has_local_type.
    " The [^.]* run can exceed the regex engine on a large flat source; the
    " exception is class-based and catchable, so degrade to "not local" ->
    " INDETERMINATE, never a CX_SY_REGEX_TOO_COMPLEX dump.
    DATA(lv_pattern) = |TYPES\\s*:?[^.]*\\b{ pv_name }\\b\\s+TYPE|.
    TRY.
        FIND REGEX lv_pattern IN pv_full_source IGNORING CASE.
        rv_yes = xsdbool( sy-subrc = 0 ).
      CATCH cx_sy_regex_too_complex.
        rv_yes = abap_false.
    ENDTRY.
  ENDMETHOD.

  METHOD resolve_type_ref.
    DATA lv_tabname TYPE dd02l-tabname.
    DATA lv_fld     TYPE dd03l-fieldname.

    CLEAR: ev_status, ev_rollname, ev_note.

    IF pv_had_ref = abap_false.
      ev_status = 'NO_DDIC_TYPE'.
      ev_note   = COND #( WHEN pv_kind = 'SELECT-OPTION'
                          THEN `Malformed SELECT-OPTIONS clause: no FOR reference found by the scan.`
                          ELSE `No TYPE/LIKE clause -- implicit CHAR(1).` ).
      RETURN.
    ENDIF.

    DATA(lv_ref) = to_upper( pv_ref ).

    IF lv_ref CS '-'.
      SPLIT lv_ref AT '-' INTO TABLE DATA(lt_ref_parts).
      IF lines( lt_ref_parts ) <> 2.
        ev_status = 'INDETERMINATE'.
        ev_note   = |{ pv_kind }: reference [{ pv_ref }] is not TABLE-FIELD; cannot resolve statically.|.
        RETURN.
      ENDIF.
      lv_tabname = lt_ref_parts[ 1 ].
      lv_fld     = lt_ref_parts[ 2 ].

      SELECT SINGLE tabname FROM dd02l INTO @DATA(lv_dd02l_hit)
        WHERE tabname = @lv_tabname AND as4local = 'A'.
      IF sy-subrc <> 0.
        ev_status = 'INDETERMINATE'.
        ev_note   = |{ pv_kind }: [{ lv_tabname }] in [{ pv_ref }] is not an active DDIC object; | &&
                    |likely a local variable.|.
        RETURN.
      ENDIF.

      SELECT SINGLE rollname FROM dd03l INTO @DATA(lv_rollname)
        WHERE tabname = @lv_tabname AND fieldname = @lv_fld AND as4local = 'A'.
      IF sy-subrc <> 0 OR lv_rollname IS INITIAL.
        ev_status = 'NO_DDIC_TYPE'.
        ev_note   = |{ pv_kind }: [{ pv_ref }] field [{ lv_fld }] carries no data element.|.
        RETURN.
      ENDIF.

      ev_status   = 'RESOLVED'.
      ev_rollname = lv_rollname.
      ev_note     = |Resolved via { pv_ref_kw } [{ pv_ref }].|.
      RETURN.
    ENDIF.

    IF is_builtin_type( lv_ref ) = abap_true.
      ev_status = 'NO_DDIC_TYPE'.
      ev_note   = |{ pv_ref_kw } { lv_ref } is a generic ABAP elementary type.|.
      RETURN.
    ENDIF.

    SELECT SINGLE rollname FROM dd04l INTO @DATA(lv_de)
      WHERE rollname = @lv_ref AND as4local = 'A'.
    IF sy-subrc = 0.
      ev_status   = 'RESOLVED'.
      ev_rollname = lv_de.
      ev_note     = |Resolved as DD04L data element [{ lv_de }] (via { pv_ref_kw }).|.
      RETURN.
    ENDIF.

    IF has_local_type( pv_name = lv_ref pv_full_source = pv_full_source ) = abap_true.
      ev_status = 'NO_DDIC_TYPE'.
      ev_note   = |{ pv_ref_kw } { lv_ref } is a local TYPES declaration.|.
      RETURN.
    ENDIF.

    ev_status = 'INDETERMINATE'.
    ev_note   = |{ pv_ref_kw } { lv_ref } is not a data element, builtin or local TYPES; | &&
                |cannot resolve statically.|.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B13_SELSCREEN -- remote-enabled, group Z_PLAIDCL.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b13_selscreen.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_REPORT) TYPE  PROGRAMM OPTIONAL
*"  EXPORTING
*"     VALUE(EV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(EV_TCODE) TYPE  TCODE
*"     VALUE(EV_MECHANISM) TYPE  STRING
*"     VALUE(EV_SOURCE_READABLE) TYPE  BOOLE_D
*"     VALUE(EV_SOURCE_COMPLETE) TYPE  BOOLE_D
*"     VALUE(EV_FOUND) TYPE  BOOLE_D
*"     VALUE(EV_FIELD_COUNT) TYPE  I
*"     VALUE(EV_INCLUDES_SCANNED) TYPE  I
*"     VALUE(ET_FIELDS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      NOT_AUTHORIZED
*"----------------------------------------------------------------------



  DATA lv_v1       TYPE symsgv.
  DATA lv_v2       TYPE symsgv.
  DATA lv_v3       TYPE symsgv.
  DATA lv_v4       TYPE symsgv.
  DATA lv_program  TYPE programm.
  DATA lv_pgmna    TYPE tstc-pgmna.
  DATA lv_exists   TYPE trdir-name.
  DATA lt_fields   TYPE ty_b13_fields.
  DATA lv_denied   TYPE abap_bool.
  DATA lv_den_text TYPE string.

  CLEAR: ev_program, ev_tcode, ev_mechanism, ev_source_readable, ev_source_complete,
         ev_found, ev_field_count, ev_includes_scanned, et_fields.

  ev_mechanism =
    `SOURCE_SCAN_HEURISTIC: READ REPORT source with INCLUDEs expanded transitively, comments ` &&
    `stripped, scanned for PARAMETERS/SELECT-OPTIONS. Not compiler-level type resolution.`.

  IF ( iv_tcode IS INITIAL AND iv_report IS INITIAL )
     OR ( iv_tcode IS NOT INITIAL AND iv_report IS NOT INITIAL ).
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = `Supply exactly one of IV_TCODE / IV_REPORT.`
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  IF iv_report IS NOT INITIAL.
    lv_program = iv_report.
  ELSE.
    SELECT SINGLE pgmna FROM tstc INTO lv_pgmna WHERE tcode = iv_tcode.
    IF sy-subrc <> 0 OR lv_pgmna IS INITIAL.
      lcl_b7_tcode_capture=>message_chunks(
        EXPORTING pv_text = |Transaction [{ iv_tcode }] not found or has no report program (TSTC-PGMNA).|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
    ENDIF.
    lv_program = lv_pgmna.
    ev_tcode   = iv_tcode.
  ENDIF.

  SELECT SINGLE name FROM trdir INTO lv_exists WHERE name = lv_program.
  IF sy-subrc <> 0.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = |Program [{ lv_program }] not found in TRDIR.|
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.
  ev_program = lv_program.

  lcl_b13_selscreen=>scan_fields(
    EXPORTING pv_program          = lv_program
    IMPORTING et_fields           = lt_fields
              ev_source_readable  = ev_source_readable
              ev_source_complete  = ev_source_complete
              ev_includes_scanned = ev_includes_scanned
              ev_denied           = lv_denied
              ev_denied_reason    = lv_den_text ).

  IF lv_denied = abap_true.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = lv_den_text
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
  ENDIF.

  ev_field_count = lines( lt_fields ).
  ev_found       = xsdbool( ev_field_count > 0 ).

  LOOP AT lt_fields INTO DATA(ls_field).
    APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
      ( |{ ls_field-fieldname }| ) ( |{ ls_field-kind }| ) ( CONV string( ls_field-obligatory ) )
      ( |{ ls_field-ddic_status }| ) ( |{ ls_field-rollname }| ) ( |{ ls_field-default_value }| ) ( |{ ls_field-note }| ) ) )
      TO et_fields.
  ENDLOOP.

ENDFUNCTION.
