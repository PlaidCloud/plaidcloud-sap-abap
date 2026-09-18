*&---------------------------------------------------------------------*
*& sc-27802 (B7 -- /PLAIDCL/RUN_TCODE, synchronous).
*&---------------------------------------------------------------------*
* Runs a report or transaction and captures its output as rows:
*   Tier A -- typed SALV capture via cl_salv_bs_runtime_info.
*   Tier B -- positional classic-list capture via LIST TO MEMORY.
*   Tier C -- refused by name, never submitted.
*
* TIER A TEXT WIDTH: SALV's runtime-info copy keeps at most 255 characters
* of a text column (A4H: a CHAR 20000 column arrives as C 255), and the
* report's own types are gone after SUBMIT. The copy also drops trailing
* blanks, so no value can be proven whole. A text column at that width is
* therefore flagged as a column (field NOTE + EV_TRUNCATED) whenever rows
* are returned, unless its DDIC length proves it is no longer than the copy.
* A genuine CHAR 255 column without DDIC is a false positive, never a silent
* cut. Tier B is no fallback: a SALV report writes no list. Tier A LENGTH is
* in characters.
*
* ZERO ROWS: tier A's ET_FIELDS come from the captured table's RTTI, not from
* its rows, so an EMPTY SALV table returns the full column list with no
* rows, not refused and with no width flag (that stays tied to rows returned).
* Only a report that produced no SALV capture at all is refused. Tier B
* infers columns from list lines, so a list with no data lines returns no
* fields.
*
* TIER B IS POSITIONAL. Columns are split at runs of two or more spaces
* in the rendered list, so a blank cell, or a value that itself contains
* two spaces, shifts every later field on that line. Rule lines (one
* unbroken run of at least 10 '-' or '=', i.e. ULINE) are never rows; a row
* of '-' / '=' VALUES is a row. A list line is dropped as page heading only
* when proven: the block H above the first rule line (within
* c_max_heading_lines) is heading when the report keeps SAP's standard page
* heading (no NO STANDARD PAGE HEADING / NEW-PAGE NO-HEADING in source), or
* when all of H, digits masked, recurs later as a contiguous run (a
* TOP-OF-PAGE repeat). Otherwise H is data and is kept. The field NOTE
* counts the dropped lines. Residual: under NO STANDARD PAGE HEADING, a
* one-block run of rows above a ULINE that recurs verbatim (digits aside)
* further down is indistinguishable from a written heading and is dropped.
* Because a repeat can be mimicked by rows, any drop proven only by a repeat
* also sets EV_TRUNCATED, so even a list whose every line was dropped (no
* fields left to carry the NOTE) never reads as an empty report. A list above c_max_list_chunks compressed chunks is
* refused before LIST_TO_ASCI expands it, so it cannot exhaust memory.
*
* RETURNED-ROWS BUDGET: rows stop at c_max_row_bytes (32 MB of UTF-16 wire
* text, B5's page budget) or IV_MAX_ROWS, whichever comes first; either
* sets EV_TRUNCATED.
*
* SELECTION VALUES: IT_SELECTION LOW/HIGH go to SUBMIT unconverted, so they
* must be in SAP's INTERNAL format -- ALPHA/NUMC with leading zeros
* ('0000001000', not '1000'), dates YYYYMMDD, decimals with '.'. An external
* value selects nothing and returns 0 rows without an error.
* SUBMIT ... WITH SELECTION-TABLE silently IGNORES a row whose SELNAME is not
* on the report's screen and runs unfiltered, and RSPARAMS silently cuts a
* long value. So before any SUBMIT (B7 in dialog and in a job, and the
* direct capture worker) every row is checked:
* - SELNAME is upper-cased and at most 8 characters, LOW/HIGH at most 45,
*   otherwise INVALID_INPUT;
* - SELNAME must be a PARAMETERS/SELECT-OPTIONS field of the program or of
*   its logical database's selection include (screen_fields, the reader that
*   check_coverage also uses), otherwise INVALID_INPUT naming it. A report
*   without a selection screen accepts no rows. When the screen can't be
*   determined (incomplete source, unreadable LDB include, scan limit), any
*   selection row raises INVALID_INPUT with the reason.
* - KIND must match that field (P = PARAMETERS, S = SELECT-OPTIONS): SUBMIT
*   ignores a row of the wrong KIND as well, so a mismatch raises
*   INVALID_INPUT naming the field and both kinds, and an OBLIGATORY field
*   counts as supplied only by a row of its own KIND.
*
* ISOLATION: in dialog/RFC the capture runs in Z_PLAIDCL_B7_CAPTURE_WORKER
* via DESTINATION 'NONE'. Inside a background job (sy-batch = 'X', i.e.
* B12) the same worker body runs in-process: the job is the isolation
* boundary (an abort cancels it, TBTCO A), a long report is not cut at the
* dialog runtime limit, and CANCEL stops the report itself.
*
* STATIC-SCAN LIMITS: a regex that hits the engine's complexity limit
* refuses the report (fail closed) instead of dumping.
*
* SOURCE AUTHORIZATION: every READ REPORT (program and each include) is
* preceded by Z_PLAIDCL_B10_CHECK_SOURCE (S_DEVELOP display, as SE38).
* One denial marks the whole source denied; B4, B7 and B13 then raise
* NOT_AUTHORIZED with the gate's message.
*
* THE CRITICAL CONSTRAINT: DYNPRO_SEND_IN_BACKGROUND is an uncatchable
* kernel abort. TRY/CATCH cx_root does not stop it, so "try Tier A,
* fall back to Tier B" cannot be built. The tier is decided statically,
* from source, BEFORE the one SUBMIT. Every blind spot in that scan is a
* production abort, so the scan fails CLOSED: anything it cannot read
* or expand (unreadable/dynamic include, include cap hit) refuses.
*
* SHARED STATIC-ANALYSIS ENGINE. lcl_b7_tcode_capture is the ONE
* implementation of source expansion, comment stripping, statement
* splitting, tier classification, the write-capability scan and the
* selection-field parse. B4 (catalog label), B6, B12 and B13 call it;
* nobody else re-implements any of it. It lives in this FM's include,
* so this FM must be activated before B4/B6/B12/B13 (group Z_PLAIDCL
* compiles as one unit).
*
* WIRE (Contract 2): IT_SELECTION, ET_FIELDS and ET_ROWS lines are
* lcl_plaidcl_codec rows. IT_SELECTION = SELNAME|KIND|SIGN|OPTION|LOW|
* HIGH. ET_FIELDS = POSITION|FIELDNAME|ROLLNAME|DATATYPE|LENGTH|
* DECIMALS|NOTE. Numbers use a leading minus.
*
* WRITES (plan §5): EV_WRITES_DETECTED / EV_INDETERMINATE are B4's
* labels, returned with every result so plan-before-run can show them.
* A detected write never refuses a run -- SAP's own authorization decides
* the write. The one exception is a write scan stopped by the regex engine
* limit: it can't vouch for the source, so B7 and the capture worker both
* refuse (RR2).
*&---------------------------------------------------------------------*

TYPES ty_b7_seltab TYPE STANDARD TABLE OF rsparams WITH DEFAULT KEY.
TYPES ty_b7_programs TYPE STANDARD TABLE OF programm WITH EMPTY KEY.

TYPES:
  BEGIN OF ty_b7_field,
    position  TYPE i,
    fieldname TYPE string,
    rollname  TYPE string,
    datatype  TYPE string,
    length    TYPE i,
    decimals  TYPE i,
    note      TYPE string,
  END OF ty_b7_field,
  ty_b7_fields TYPE STANDARD TABLE OF ty_b7_field WITH EMPTY KEY,

  BEGIN OF ty_b7_meta,
    tier            TYPE c LENGTH 1,
    tier_label      TYPE string,
    program         TYPE programm,
    tcode           TYPE tcode,
    refused         TYPE abap_bool,
    refusal_reason  TYPE string,
    row_count       TYPE i,
    column_count    TYPE i,
    truncated       TYPE abap_bool,
    delimiter       TYPE c LENGTH 1,
    skipped_columns TYPE string,
    std_heading     TYPE abap_bool,   " tier B: SAP's standard page heading is on
  END OF ty_b7_meta,

  BEGIN OF ty_b7_src_line,
    incl   TYPE programm,
    line   TYPE i,
    code   TYPE string,   " comments removed, literals intact
    masked TYPE string,   " same length as code, literal contents replaced by 'x'
  END OF ty_b7_src_line,
  ty_b7_src_lines TYPE STANDARD TABLE OF ty_b7_src_line WITH EMPTY KEY,

  BEGIN OF ty_b7_finding,
    incl      TYPE programm,
    line      TYPE i,
    stmt_type TYPE string,
    target    TYPE string,
    certainty TYPE string,   " DEFINITE / INDETERMINATE
    src_line  TYPE string,
  END OF ty_b7_finding,
  ty_b7_findings TYPE STANDARD TABLE OF ty_b7_finding WITH EMPTY KEY,

  BEGIN OF ty_b7_source,
    program           TYPE programm,
    readable          TYPE abap_bool,
    complete          TYPE abap_bool,
    includes_expanded TYPE i,
    denied            TYPE abap_bool,
    denied_reason     TYPE string,
    src               TYPE ty_b7_src_lines,
    issues            TYPE ty_b7_findings,
  END OF ty_b7_source,

  BEGIN OF ty_b7_stmt,
    incl   TYPE programm,
    line   TYPE i,
    code   TYPE string,
    masked TYPE string,
  END OF ty_b7_stmt,
  ty_b7_stmts TYPE STANDARD TABLE OF ty_b7_stmt WITH EMPTY KEY,

  BEGIN OF ty_b7_selfield,
    name       TYPE string,
    kind       TYPE c LENGTH 1,   " P = PARAMETERS, S = SELECT-OPTIONS
    obligatory TYPE abap_bool,
    clause     TYPE string,
    ldb        TYPE string,       " set when the field comes from the LDB screen
  END OF ty_b7_selfield,
  ty_b7_selfields TYPE STANDARD TABLE OF ty_b7_selfield WITH EMPTY KEY,

  BEGIN OF ty_b7_write_scan,
    source_readable   TYPE abap_bool,
    source_lines_seen TYPE i,
    includes_expanded TYPE i,
    writes_detected   TYPE abap_bool,
    indeterminate     TYPE abap_bool,
    findings          TYPE ty_b7_findings,
    scan_note         TYPE string,
  END OF ty_b7_write_scan.

CLASS lcl_b7_tcode_capture DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_delimiter TYPE c LENGTH 1 VALUE '|'.
    CONSTANTS c_max_rows TYPE i VALUE 50000.
    CONSTANTS c_max_includes TYPE i VALUE 300.
    CONSTANTS c_max_depth TYPE i VALUE 12.
    " LIST_TO_ASCI expands the whole list into 1024-char (2 KB) lines at once.
    " Measured on A4H: 60000 short, near-identical lines = 194 chunks, the most
    " compressible case (~310 lines per chunk). 500 chunks therefore caps one
    " call at ~155000 lines (~320 MB); less compressible lists stop sooner.
    CONSTANTS c_max_list_chunks TYPE i VALUE 500.
    CONSTANTS c_max_heading_lines TYPE i VALUE 20.
    " RR1: B5's 32 MB page budget, counted the same way (2 bytes per character).
    CONSTANTS c_max_row_bytes TYPE int8 VALUE 33554432.
    CONSTANTS c_err_invalid_input TYPE i VALUE 1.
    CONSTANTS c_err_not_found TYPE i VALUE 2.
    CONSTANTS c_err_not_authorized TYPE i VALUE 3.
    CONSTANTS c_err_max_rows TYPE i VALUE 4.

    CLASS-METHODS read_source
      IMPORTING pv_program       TYPE programm
      RETURNING VALUE(rs_source) TYPE ty_b7_source.

    CLASS-METHODS clean_line
      IMPORTING pv_line   TYPE string
      EXPORTING ev_code   TYPE string
                ev_masked TYPE string.

    CLASS-METHODS statements
      IMPORTING ps_source       TYPE ty_b7_source
      RETURNING VALUE(rt_stmts) TYPE ty_b7_stmts.

    CLASS-METHODS selection_fields
      IMPORTING pt_stmts         TYPE ty_b7_stmts
      RETURNING VALUE(rt_fields) TYPE ty_b7_selfields.

    CLASS-METHODS classify_tier
      IMPORTING pv_program     TYPE programm
      RETURNING VALUE(rs_meta) TYPE ty_b7_meta.

    CLASS-METHODS classify_source
      IMPORTING ps_source      TYPE ty_b7_source
      RETURNING VALUE(rs_meta) TYPE ty_b7_meta.

    CLASS-METHODS scan_writes
      IMPORTING ps_source      TYPE ty_b7_source
      RETURNING VALUE(rs_scan) TYPE ty_b7_write_scan.

    CLASS-METHODS check_selection_coverage
      IMPORTING pv_program        TYPE programm
                pt_selection      TYPE ty_b7_seltab
      EXPORTING ev_ok             TYPE abap_bool
                ev_missing_fields TYPE string.

    CLASS-METHODS check_coverage
      IMPORTING ps_source         TYPE ty_b7_source
                pt_selection      TYPE ty_b7_seltab
      EXPORTING ev_ok             TYPE abap_bool
                ev_missing_fields TYPE string.

    " The report's selection screen: program fields plus its LDB's. ev_known
    " is false (with ev_reason) when the screen can't be determined.
    CLASS-METHODS screen_fields
      IMPORTING ps_source  TYPE ty_b7_source
      EXPORTING et_fields  TYPE ty_b7_selfields
                ev_known   TYPE abap_bool
                ev_reason  TYPE string.

    " Every IT_SELECTION row must name a field of that screen.
    CLASS-METHODS check_selnames
      IMPORTING ps_source    TYPE ty_b7_source
                pt_selection TYPE ty_b7_seltab
      EXPORTING ev_ok        TYPE abap_bool
                ev_error     TYPE string.

    " Precondition: ps_meta_in-tier IN ('A','B') and not refused.
    CLASS-METHODS capture
      IMPORTING pv_program   TYPE programm
                ps_meta_in   TYPE ty_b7_meta
                pt_selection TYPE ty_b7_seltab
                pv_max_rows  TYPE i DEFAULT 10000
      EXPORTING es_meta      TYPE ty_b7_meta
                et_fields    TYPE ty_b7_fields
                et_rows      TYPE string_table.

    CLASS-METHODS split_columns
      IMPORTING pv_line        TYPE string
      RETURNING VALUE(rt_cols) TYPE string_table.

    CLASS-METHODS decode_selection
      IMPORTING pt_wire  TYPE string_table
      EXPORTING et_sel   TYPE ty_b7_seltab
                ev_ok    TYPE abap_bool
                ev_error TYPE string.

    CLASS-METHODS encode_fields
      IMPORTING pt_fields      TYPE ty_b7_fields
      RETURNING VALUE(rt_wire) TYPE string_table.

    CLASS-METHODS flatten_meta
      IMPORTING ps_meta            TYPE ty_b7_meta
      EXPORTING ev_tier            TYPE string
                ev_tier_label      TYPE string
                ev_program         TYPE programm
                ev_tcode           TYPE tcode
                ev_refused         TYPE abap_bool
                ev_refusal_reason  TYPE string
                ev_row_count       TYPE i
                ev_column_count    TYPE i
                ev_truncated       TYPE abap_bool
                ev_delimiter       TYPE string
                ev_skipped_columns TYPE string.

    " The capture worker's whole body: input checks, the Contract-1 gate, the
    " source gate, classification, coverage and the one SUBMIT. The worker FM
    " runs it behind DESTINATION 'NONE'; B7 runs it in-process inside a
    " background job (RB1). ev_error is 0 or a c_err_* key; the caller raises
    " the matching exception with ev_error_text (a method can't RAISE classic).
    CLASS-METHODS worker_body
      IMPORTING pv_program    TYPE programm
                pv_tcode      TYPE tcode
                pv_max_rows   TYPE i
                pt_wire_sel   TYPE string_table
      EXPORTING es_meta       TYPE ty_b7_meta
                et_fields     TYPE string_table
                et_rows       TYPE string_table
                ev_error      TYPE i
                ev_error_text TYPE string.

    " Contract 3: MESSAGE e001(00) takes the text as four 50-char chunks.
    CLASS-METHODS message_chunks
      IMPORTING pv_text TYPE string
      EXPORTING ev_v1   TYPE symsgv
                ev_v2   TYPE symsgv
                ev_v3   TYPE symsgv
                ev_v4   TYPE symsgv.

  PRIVATE SECTION.
    CLASS-METHODS expand_include
      IMPORTING pv_include TYPE programm
                pv_depth   TYPE i
      EXPORTING ev_read_ok TYPE abap_bool
      CHANGING  cs_source  TYPE ty_b7_source
                ct_seen    TYPE ty_b7_programs.

    CLASS-METHODS is_list_write
      IMPORTING pv_masked     TYPE string
      RETURNING VALUE(rv_yes) TYPE abap_bool.

    CLASS-METHODS is_separator
      IMPORTING pv_line       TYPE string
      RETURNING VALUE(rv_yes) TYPE abap_bool.

    CLASS-METHODS mask_digits
      IMPORTING pv_line       TYPE string
      RETURNING VALUE(rv_out) TYPE string.

    CLASS-METHODS has_value
      IMPORTING pt_selection  TYPE ty_b7_seltab
                pv_name       TYPE string
                pv_kind       TYPE rsparams-kind
      RETURNING VALUE(rv_yes) TYPE abap_bool.

    CLASS-METHODS is_known_updating_fm
      IMPORTING pv_fm_name_upper TYPE string
      RETURNING VALUE(rv_known)  TYPE abap_bool.

    CLASS-METHODS refuse
      IMPORTING pv_reason TYPE string
      CHANGING  cs_meta   TYPE ty_b7_meta.

    CLASS-METHODS capture_tier_a
      IMPORTING pv_program   TYPE programm
                pt_selection TYPE ty_b7_seltab
                pv_max_rows  TYPE i
      EXPORTING et_fields    TYPE ty_b7_fields
                et_rows      TYPE string_table
      CHANGING  cs_meta      TYPE ty_b7_meta.

    CLASS-METHODS capture_tier_b
      IMPORTING pv_program   TYPE programm
                pt_selection TYPE ty_b7_seltab
                pv_max_rows  TYPE i
      EXPORTING et_fields    TYPE ty_b7_fields
                et_rows      TYPE string_table
      CHANGING  cs_meta      TYPE ty_b7_meta.

    " One tier-B row as a codec line, padded to pv_cols fields (pv_cols >= 1).
    CLASS-METHODS encode_positional
      IMPORTING pt_cols      TYPE string_table
                pv_cols      TYPE i
      RETURNING VALUE(rv_row) TYPE string.
ENDCLASS.

CLASS lcl_b7_tcode_capture IMPLEMENTATION.

  METHOD read_source.
    DATA lt_seen    TYPE ty_b7_programs.
    DATA lv_read_ok TYPE abap_bool.

    rs_source-program  = pv_program.
    rs_source-readable = abap_true.
    rs_source-complete = abap_true.
    APPEND pv_program TO lt_seen.

    expand_include(
      EXPORTING pv_include = pv_program
                pv_depth   = 0
      IMPORTING ev_read_ok = lv_read_ok
      CHANGING  cs_source  = rs_source
                ct_seen    = lt_seen ).
    IF rs_source-denied = abap_true.
      rs_source-readable = abap_false.
      rs_source-complete = abap_false.
      RETURN.
    ENDIF.
    IF lv_read_ok = abap_false.
      rs_source-readable = abap_false.
      rs_source-complete = abap_false.
      APPEND VALUE #( incl = pv_program stmt_type = 'SOURCE_UNREADABLE' target = pv_program
                      certainty = 'INDETERMINATE'
                      src_line = |READ REPORT failed for [{ pv_program }]| ) TO rs_source-issues.
    ENDIF.
  ENDMETHOD.

  METHOD expand_include.
    DATA lt_raw     TYPE string_table.
    DATA lv_code    TYPE string.
    DATA lv_masked  TYPE string.
    DATA lv_name    TYPE string.
    DATA lv_ns      TYPE string.
    DATA lv_iffound TYPE string.
    DATA lv_inc     TYPE programm.
    DATA lv_sub_ok  TYPE abap_bool.

    ev_read_ok = abap_false.
    IF cs_source-denied = abap_true.
      RETURN.
    ENDIF.

    " S1/S2: SAP's own SE38 display check (S_DEVELOP) before EVERY source
    " read. A denied program or include denies the whole scan; the callers
    " (B4/B7/B13) turn cs_source-denied into NOT_AUTHORIZED.
    DATA lv_v1 TYPE symsgv.
    DATA lv_v2 TYPE symsgv.
    DATA lv_v3 TYPE symsgv.
    DATA lv_v4 TYPE symsgv.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_SOURCE'
      EXPORTING iv_program        = pv_include
      EXCEPTIONS not_authorized    = 1
                 program_not_found = 2
                 OTHERS            = 3.
    CASE sy-subrc.
      WHEN 0.
      WHEN 2.
        " Not in TRDIR: an unreadable include, handled like READ REPORT failing.
        RETURN.
      WHEN OTHERS.
        lv_v1 = sy-msgv1. lv_v2 = sy-msgv2. lv_v3 = sy-msgv3. lv_v4 = sy-msgv4.
        cs_source-denied        = abap_true.
        cs_source-denied_reason = condense( |{ lv_v1 }{ lv_v2 }{ lv_v3 }{ lv_v4 }| ).
        IF cs_source-denied_reason IS INITIAL.
          cs_source-denied_reason = |Not authorized to read source of [{ pv_include }] (S_DEVELOP display).|.
        ENDIF.
        RETURN.
    ENDCASE.

    READ REPORT pv_include INTO lt_raw.
    IF sy-subrc <> 0 OR ( pv_depth = 0 AND lt_raw IS INITIAL ).
      RETURN.
    ENDIF.
    ev_read_ok = abap_true.

    TRY.
        LOOP AT lt_raw INTO DATA(lv_raw).
          IF cs_source-denied = abap_true.   " a nested include was denied: stop expanding
            RETURN.
          ENDIF.
          DATA(lv_lineno) = sy-tabix.
          clean_line( EXPORTING pv_line = lv_raw IMPORTING ev_code = lv_code ev_masked = lv_masked ).
          IF lv_masked CO ` `.
            CONTINUE.
          ENDIF.
          APPEND VALUE #( incl = pv_include line = lv_lineno code = lv_code masked = lv_masked ) TO cs_source-src.

          " INCLUDE after another statement on the same line: not parsed, so
          " the source is not known to be complete.
          FIND REGEX '\.\s*INCLUDE\s' IN lv_masked IGNORING CASE.
          IF sy-subrc = 0.
            cs_source-complete = abap_false.
            APPEND VALUE #( incl = pv_include line = lv_lineno stmt_type = 'INCLUDE_DYNAMIC' target = '(unparsed)'
                            certainty = 'INDETERMINATE' src_line = lv_code ) TO cs_source-issues.
            CONTINUE.
          ENDIF.

          FIND REGEX '^\s*INCLUDE\b' IN lv_masked IGNORING CASE.
          IF sy-subrc <> 0.
            CONTINUE.
          ENDIF.
          FIND REGEX '^\s*INCLUDE\s+(STRUCTURE|TYPE)\s' IN lv_masked IGNORING CASE.
          IF sy-subrc = 0.
            CONTINUE.
          ENDIF.

          CLEAR: lv_name, lv_ns, lv_iffound.
          FIND REGEX '^\s*INCLUDE\s+((/\w+/)?[\w<>~]+)\s*(IF\s+FOUND)?\s*\.' IN lv_code IGNORING CASE
            SUBMATCHES lv_name lv_ns lv_iffound.
          IF sy-subrc <> 0.
            cs_source-complete = abap_false.
            APPEND VALUE #( incl = pv_include line = lv_lineno stmt_type = 'INCLUDE_DYNAMIC' target = '(dynamic)'
                            certainty = 'INDETERMINATE' src_line = lv_code ) TO cs_source-issues.
            CONTINUE.
          ENDIF.

          lv_inc = to_upper( lv_name ).
          IF line_exists( ct_seen[ table_line = lv_inc ] ).
            CONTINUE.
          ENDIF.
          IF pv_depth >= c_max_depth OR lines( ct_seen ) > c_max_includes.
            cs_source-complete = abap_false.
            APPEND VALUE #( incl = pv_include line = lv_lineno stmt_type = 'INCLUDE_CAP' target = lv_inc
                            certainty = 'INDETERMINATE'
                            src_line = |include cap reached (depth { c_max_depth }, count { c_max_includes })| )
              TO cs_source-issues.
            CONTINUE.
          ENDIF.
          APPEND lv_inc TO ct_seen.

          expand_include(
            EXPORTING pv_include = lv_inc
                      pv_depth   = pv_depth + 1
            IMPORTING ev_read_ok = lv_sub_ok
            CHANGING  cs_source  = cs_source
                      ct_seen    = ct_seen ).
          IF lv_sub_ok = abap_true.
            cs_source-includes_expanded = cs_source-includes_expanded + 1.
          ELSEIF lv_iffound IS INITIAL.
            cs_source-complete = abap_false.
            APPEND VALUE #( incl = pv_include line = lv_lineno stmt_type = 'INCLUDE_UNREADABLE' target = lv_inc
                            certainty = 'INDETERMINATE'
                            src_line = |include [{ lv_inc }] could not be read| ) TO cs_source-issues.
          ENDIF.
        ENDLOOP.
      CATCH cx_sy_regex_too_complex INTO DATA(lx_regex).
        " RR2: fail closed -- an include the scan cannot finish is not complete.
        cs_source-complete = abap_false.
        APPEND VALUE #( incl = pv_include stmt_type = 'REGEX_TOO_COMPLEX' target = pv_include
                        certainty = 'INDETERMINATE'
                        src_line = |include scan stopped: { lx_regex->get_text( ) }| ) TO cs_source-issues.
    ENDTRY.
  ENDMETHOD.

  METHOD clean_line.
    " '*' is a comment only in column 1; '"' opens a comment anywhere
    " outside a '...' / `...` literal or a |...| template.
    ev_code   = pv_line.
    ev_masked = pv_line.
    IF pv_line IS INITIAL.
      RETURN.
    ENDIF.
    IF substring( val = pv_line off = 0 len = 1 ) = '*'.
      CLEAR: ev_code, ev_masked.
      RETURN.
    ENDIF.
    IF pv_line NA '"''`|'.
      RETURN.
    ENDIF.

    CONSTANTS: lc_code     TYPE i VALUE 0,
               lc_quote    TYPE i VALUE 1,
               lc_backtick TYPE i VALUE 2,
               lc_template TYPE i VALUE 3,
               lc_embedded TYPE i VALUE 4,
               lc_emb_lit  TYPE i VALUE 5.
    DATA lv_state TYPE i VALUE lc_code.
    DATA lv_mask  TYPE string.
    DATA lv_next  TYPE string.
    DATA(lv_len) = strlen( pv_line ).
    DATA(lv_i)   = 0.

    WHILE lv_i < lv_len.
      DATA(lv_c) = substring( val = pv_line off = lv_i len = 1 ).
      CLEAR lv_next.
      IF lv_i + 1 < lv_len.
        lv_next = substring( val = pv_line off = lv_i + 1 len = 1 ).
      ENDIF.

      CASE lv_state.
        WHEN lc_code.
          IF lv_c = '"'.
            ev_code   = substring( val = pv_line off = 0 len = lv_i ).
            ev_masked = lv_mask.
            RETURN.
          ELSEIF lv_c = `'`.
            lv_state = lc_quote.
          ELSEIF lv_c = '`'.
            lv_state = lc_backtick.
          ELSEIF lv_c = '|'.
            lv_state = lc_template.
          ENDIF.
          lv_mask = lv_mask && lv_c.

        WHEN lc_quote OR lc_backtick.
          IF ( lv_state = lc_quote AND lv_c = `'` ) OR ( lv_state = lc_backtick AND lv_c = '`' ).
            IF lv_next = lv_c.
              lv_mask = lv_mask && `xx`.
              lv_i = lv_i + 2.
              CONTINUE.
            ENDIF.
            lv_state = lc_code.
            lv_mask = lv_mask && lv_c.
          ELSE.
            lv_mask = lv_mask && `x`.
          ENDIF.

        WHEN lc_template.
          IF lv_c = '\' AND lv_next IS NOT INITIAL.
            lv_mask = lv_mask && `xx`.
            lv_i = lv_i + 2.
            CONTINUE.
          ELSEIF lv_c = '{'.
            lv_state = lc_embedded.
            lv_mask = lv_mask && `x`.
          ELSEIF lv_c = '|'.
            lv_state = lc_code.
            lv_mask = lv_mask && lv_c.
          ELSE.
            lv_mask = lv_mask && `x`.
          ENDIF.

        WHEN lc_embedded.
          IF lv_c = '}'.
            lv_state = lc_template.
          ELSEIF lv_c = `'`.
            lv_state = lc_emb_lit.
          ENDIF.
          lv_mask = lv_mask && `x`.

        WHEN lc_emb_lit.
          IF lv_c = `'`.
            lv_state = lc_embedded.
          ENDIF.
          lv_mask = lv_mask && `x`.
      ENDCASE.
      lv_i = lv_i + 1.
    ENDWHILE.
    ev_masked = lv_mask.
  ENDMETHOD.

  METHOD statements.
    " RR2: a statement's pieces are collected and joined once when it ends.
    " Growing the statement string piece by piece was quadratic in its length.
    DATA ls_stmt  TYPE ty_b7_stmt.
    DATA lt_code  TYPE string_table.
    DATA lt_mask  TYPE string_table.
    DATA lv_blank TYPE abap_bool VALUE abap_true.
    DATA lv_found TYPE abap_bool.
    DATA lv_code  TYPE string.
    DATA lv_mask  TYPE string.
    DATA lv_off   TYPE i.

    LOOP AT ps_source-src INTO DATA(ls_line).
      lv_code = ls_line-code.
      lv_mask = ls_line-masked.
      DO.
        FIND FIRST OCCURRENCE OF '.' IN lv_mask MATCH OFFSET lv_off.
        lv_found = xsdbool( sy-subrc = 0 ).
        IF lv_found = abap_false AND lv_mask CO ` `.
          EXIT.
        ENDIF.
        IF lv_blank = abap_true.
          ls_stmt-incl = ls_line-incl.
          ls_stmt-line = ls_line-line.
        ENDIF.
        IF lv_found = abap_false.
          APPEND lv_code TO lt_code.
          APPEND lv_mask TO lt_mask.
          lv_blank = abap_false.
          EXIT.
        ENDIF.
        APPEND substring( val = lv_code off = 0 len = lv_off ) TO lt_code.
        APPEND substring( val = lv_mask off = 0 len = lv_off ) TO lt_mask.
        ls_stmt-code   = concat_lines_of( table = lt_code sep = ` ` ).
        ls_stmt-masked = concat_lines_of( table = lt_mask sep = ` ` ).
        APPEND ls_stmt TO rt_stmts.
        CLEAR: ls_stmt, lt_code, lt_mask.
        lv_blank = abap_true.
        lv_code = substring( val = lv_code off = lv_off + 1 ).
        lv_mask = substring( val = lv_mask off = lv_off + 1 ).
      ENDDO.
    ENDLOOP.
    IF lv_blank = abap_false.
      ls_stmt-code   = concat_lines_of( table = lt_code sep = ` ` ).
      ls_stmt-masked = concat_lines_of( table = lt_mask sep = ` ` ).
      APPEND ls_stmt TO rt_stmts.
    ENDIF.
  ENDMETHOD.

  METHOD selection_fields.
    DATA lv_kw     TYPE string.
    DATA lv_kwlen  TYPE i.
    DATA lv_code   TYPE string.
    DATA lv_mask   TYPE string.
    DATA lv_ccode  TYPE string.
    DATA lv_cmask  TYPE string.
    DATA lv_off    TYPE i.
    DATA lv_name   TYPE string.
    DATA lv_last   TYPE abap_bool.
    DATA lv_kind   TYPE c LENGTH 1.
    DATA lv_oblig  TYPE abap_bool.

    LOOP AT pt_stmts INTO DATA(ls_stmt).
      FIND REGEX '^\s*(PARAMETERS|SELECT-OPTIONS)\s*:?' IN ls_stmt-masked IGNORING CASE
        MATCH LENGTH lv_kwlen SUBMATCHES lv_kw.
      IF sy-subrc <> 0.
        CONTINUE.
      ENDIF.
      lv_kind = COND #( WHEN to_upper( lv_kw ) = 'PARAMETERS' THEN 'P' ELSE 'S' ).

      " Chained declarations (PARAMETERS: a ..., b ... OBLIGATORY.) are one
      " statement; each comma-separated clause is its own field.
      lv_code = substring( val = ls_stmt-code off = lv_kwlen ).
      lv_mask = substring( val = ls_stmt-masked off = lv_kwlen ).
      lv_last = abap_false.
      WHILE lv_last = abap_false.
        FIND FIRST OCCURRENCE OF ',' IN lv_mask MATCH OFFSET lv_off.
        IF sy-subrc = 0.
          lv_ccode = substring( val = lv_code off = 0 len = lv_off ).
          lv_cmask = substring( val = lv_mask off = 0 len = lv_off ).
          lv_code  = substring( val = lv_code off = lv_off + 1 ).
          lv_mask  = substring( val = lv_mask off = lv_off + 1 ).
        ELSE.
          lv_ccode = lv_code.
          lv_cmask = lv_mask.
          lv_last  = abap_true.
        ENDIF.

        CLEAR lv_name.
        FIND REGEX '^\s*(\w+)' IN lv_cmask SUBMATCHES lv_name.
        IF sy-subrc <> 0.
          CONTINUE.
        ENDIF.
        FIND REGEX '\bOBLIGATORY\b' IN lv_cmask IGNORING CASE.
        lv_oblig = xsdbool( sy-subrc = 0 ).
        APPEND VALUE #( name       = to_upper( lv_name )
                        kind       = lv_kind
                        obligatory = lv_oblig
                        clause     = lv_ccode ) TO rt_fields.
      ENDWHILE.
    ENDLOOP.
  ENDMETHOD.

  METHOD refuse.
    cs_meta-tier           = 'C'.
    cs_meta-tier_label     = 'REFUSED'.
    cs_meta-refused        = abap_true.
    cs_meta-refusal_reason = pv_reason.
  ENDMETHOD.

  METHOD classify_tier.
    rs_meta = classify_source( read_source( pv_program ) ).
  ENDMETHOD.

  METHOD classify_source.
    DATA lv_subc   TYPE trdir-subc.
    DATA lv_off    TYPE i.
    DATA lv_len    TYPE i.
    DATA lv_screen TYPE string.
    DATA lv_salv    TYPE abap_bool.
    DATA lv_write   TYPE abap_bool.
    DATA lv_no_head TYPE abap_bool.
    DATA lx_scan    TYPE REF TO cx_root.

    rs_meta-program   = ps_source-program.
    rs_meta-delimiter = c_delimiter.

    SELECT SINGLE subc FROM trdir INTO lv_subc WHERE name = ps_source-program.
    IF sy-subrc <> 0.
      refuse( EXPORTING pv_reason = |Refused: program [{ ps_source-program }] not found in TRDIR.|
              CHANGING cs_meta = rs_meta ).
      RETURN.
    ENDIF.
    IF lv_subc <> '1'.
      refuse( EXPORTING pv_reason = |Refused: [{ ps_source-program }] has TRDIR-SUBC=[{ lv_subc }], not '1' | &&
                                    |(executable report); SUBMIT cannot run it.|
              CHANGING cs_meta = rs_meta ).
      RETURN.
    ENDIF.
    IF ps_source-readable = abap_false.
      refuse( EXPORTING pv_reason = |Refused: could not READ REPORT [{ ps_source-program }] to classify it statically.|
              CHANGING cs_meta = rs_meta ).
      RETURN.
    ENDIF.
    IF ps_source-complete = abap_false.
      DATA(ls_issue) = VALUE ty_b7_finding( ps_source-issues[ 1 ] OPTIONAL ).
      refuse( EXPORTING pv_reason = |Refused: source of [{ ps_source-program }] could not be fully expanded | &&
                                    |({ lines( ps_source-issues ) } issue(s), first { ls_issue-stmt_type } | &&
                                    |[{ ls_issue-target }] in [{ ls_issue-incl }] line { ls_issue-line }); | &&
                                    |its output mechanism is indeterminate.|
              CHANGING cs_meta = rs_meta ).
      RETURN.
    ENDIF.

    " CL_GUI_\w+ replaces the 7 enumerated control names; NEW-PAGE PRINT ON
    " without NO DIALOG is checked separately because it needs a lookahead.
    DATA(lv_screen_re) =
      `\b(CALL\s+SCREEN|CALL\s+DIALOG|SET\s+SCREEN|LEAVE\s+TO\s+SCREEN|LEAVE\s+TO\s+TRANSACTION|` &&
      `CALL\s+SELECTION-SCREEN|VIA\s+SELECTION-SCREEN|CALL\s+TRANSACTION|` &&
      `REUSE_ALV_\w*|POPUP_\w*|F4IF_\w*|GET_PRINT_PARAMETERS|GUI_UPLOAD|GUI_DOWNLOAD|` &&
      `CL_SALV_TREE|CL_SALV_HIERSEQ_TABLE|CL_SALV_GUI_TABLE_IDA|CL_GUI_\w+)`.

    DATA(lt_stmts) = statements( ps_source ).
    TRY.
        LOOP AT lt_stmts INTO DATA(ls_stmt).
          " Code (literals intact) so 'REUSE_ALV_GRID_DISPLAY' in CALL FUNCTION
          " is seen; a marker inside ordinary text refuses too, which is the
          " safe direction.
          FIND REGEX lv_screen_re IN ls_stmt-code IGNORING CASE MATCH OFFSET lv_off MATCH LENGTH lv_len.
          IF sy-subrc <> 0.
            FIND REGEX 'NEW-PAGE\s+PRINT\s+ON\b(?!.*\bNO\s+DIALOG\b)' IN ls_stmt-code IGNORING CASE
              MATCH OFFSET lv_off MATCH LENGTH lv_len.
          ENDIF.
          IF sy-subrc = 0.
            lv_screen = |{ substring( val = ls_stmt-code off = lv_off len = lv_len ) } | &&
                        |([{ ls_stmt-incl }] line { ls_stmt-line })|.
            EXIT.
          ENDIF.
          FIND REGEX '\bCL_SALV_TABLE\b' IN ls_stmt-masked IGNORING CASE.
          IF sy-subrc = 0.
            lv_salv = abap_true.
          ENDIF.
          " DB1: without these, SAP prints its standard page heading first.
          FIND REGEX '\bNO\s+STANDARD\s+PAGE\s+HEADING\b|\bNO-HEADING\b' IN ls_stmt-masked IGNORING CASE.
          IF sy-subrc = 0.
            lv_no_head = abap_true.
          ENDIF.
          IF lv_write = abap_false.
            lv_write = is_list_write( ls_stmt-masked ).
          ENDIF.
        ENDLOOP.
      CATCH cx_sy_regex_too_complex cx_sy_no_handler INTO lx_scan.
        " RR2: fail closed. The limit hit inside is_list_write, which has no
        " RAISING clause, arrives wrapped as CX_SY_NO_HANDLER.
        refuse( EXPORTING pv_reason = |Refused: the static scan of [{ ps_source-program }] stopped at | &&
                                      |[{ ls_stmt-incl }] line { ls_stmt-line } ({ lx_scan->get_text( ) }); | &&
                                      |its output mechanism is indeterminate.|
                CHANGING cs_meta = rs_meta ).
        RETURN.
    ENDTRY.

    IF lv_screen IS NOT INITIAL.
      refuse( EXPORTING pv_reason = |Refused: [{ ps_source-program }] source contains { lv_screen }, which paints | &&
                                    |a screen/control; headless capture would risk DYNPRO_SEND_IN_BACKGROUND.|
              CHANGING cs_meta = rs_meta ).
      RETURN.
    ENDIF.
    IF lv_salv = abap_true.
      rs_meta-tier       = 'A'.
      rs_meta-tier_label = 'TYPED_SALV'.
      RETURN.
    ENDIF.
    IF lv_write = abap_true.
      rs_meta-tier        = 'B'.
      rs_meta-tier_label  = 'POSITIONAL_WRITE_LIST'.
      rs_meta-std_heading = xsdbool( lv_no_head = abap_false ).
      RETURN.
    ENDIF.
    refuse( EXPORTING pv_reason = |Refused: [{ ps_source-program }] shows no CL_SALV_TABLE and no list WRITE; | &&
                                  |cannot classify its output mechanism statically.|
            CHANGING cs_meta = rs_meta ).
  ENDMETHOD.

  METHOD is_list_write.
    " WRITE x TO y only formats into a variable; any chained part
    " without TO writes to the list.
    DATA lv_len  TYPE i.
    DATA lv_body TYPE string.
    DATA lv_pad  TYPE string.
    FIND REGEX '^\s*WRITE\b\s*:?' IN pv_masked IGNORING CASE MATCH LENGTH lv_len.
    IF sy-subrc <> 0.
      RETURN.
    ENDIF.
    lv_body = substring( val = pv_masked off = lv_len ).
    SPLIT lv_body AT ',' INTO TABLE DATA(lt_parts).
    LOOP AT lt_parts INTO DATA(lv_part).
      IF lv_part CO ` `.
        CONTINUE.
      ENDIF.
      lv_pad = | { lv_part } |.
      FIND REGEX '\sTO\s' IN lv_pad IGNORING CASE.
      IF sy-subrc <> 0.
        rv_yes = abap_true.
        RETURN.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD is_separator.
    " DN-a: a rule line (ULINE / sy-uline) is ONE unbroken run of '-' or '='.
    " A row of dash VALUES ('  -     -  ') has gaps, and a short run such as
    " a '---' cell is a value, so neither is a separator.
    DATA(lv_c) = condense( pv_line ).
    IF strlen( lv_c ) >= 10 AND ( lv_c CO '-' OR lv_c CO '=' ).
      rv_yes = abap_true.
    ENDIF.
  ENDMETHOD.

  METHOD mask_digits.
    rv_out = pv_line.
    TRANSLATE rv_out USING '102030405060708090'.
  ENDMETHOD.

  METHOD is_known_updating_fm.
    DATA(lt_known) = VALUE string_table(
      ( `DDIF_TABL_PUT` ) ( `DDIF_TABL_ACTIVATE` ) ( `DDIF_FIEL_PUT` ) ( `DDIF_DOMA_PUT` ) ( `DDIF_DTEL_PUT` )
      ( `RSAQ_GENERATE_PROGRAM` )
      ( `BAPI_TRANSACTION_COMMIT` ) ( `BAPI_TRANSACTION_ROLLBACK` )
      ( `BAPI_USER_CREATE1` ) ( `BAPI_USER_CHANGE` ) ( `BAPI_USER_DELETE` )
      ( `BAPI_USER_LOCK` ) ( `BAPI_USER_UNLOCK` )
      ( `SUSR_USER_CHANGE_PASSWORD_RFC` ) ( `SUSR_USER_CHANGE` )
      ( `RS_TRANSPORT_COPY` ) ( `TR_TADIR_INTERFACE` ) ).
    rv_known = xsdbool( line_exists( lt_known[ table_line = pv_fm_name_upper ] ) ).
  ENDMETHOD.

  METHOD scan_writes.
    " Label only (plan §5). Regex over comment-stripped source, not a
    " parser: it cannot tell a DB table from a local structure, so each
    " rule is a documented heuristic. Dynamic or unexpandable constructs
    " are INDETERMINATE, never "no writes".
    DATA lv_tab    TYPE string.
    DATA lv_fm     TYPE string.
    DATA lv_itab   TYPE abap_bool.

    rs_scan-source_readable   = ps_source-readable.
    rs_scan-source_lines_seen = lines( ps_source-src ).
    rs_scan-includes_expanded = ps_source-includes_expanded.
    rs_scan-findings          = ps_source-issues.
    rs_scan-indeterminate     = xsdbool( ps_source-complete = abap_false ).

    TRY.
        LOOP AT ps_source-src INTO DATA(ls_src).
          DATA(lv_line) = ls_src-code.
          DATA(ls_hit)  = VALUE ty_b7_finding( incl = ls_src-incl line = ls_src-line src_line = lv_line ).

          " --- INSERT ---
          FIND REGEX '^\s*INSERT\s*\(' IN lv_line IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-indeterminate = abap_true.
            ls_hit-stmt_type = 'INSERT'. ls_hit-target = '(dynamic)'. ls_hit-certainty = 'INDETERMINATE'.
            APPEND ls_hit TO rs_scan-findings.
          ELSE.
            FIND REGEX 'INTO\s+TABLE|INDEX|LINES\s+OF|INITIAL\s+LINE' IN lv_line IGNORING CASE.
            lv_itab = xsdbool( sy-subrc = 0 ).
            FIND REGEX `INSERT\s+INTO\s+(\w+)` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
            IF sy-subrc <> 0.
              FIND REGEX `^\s*INSERT\s+(\w+)\s+FROM\s` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
            ENDIF.
            IF sy-subrc = 0 AND lv_itab = abap_false.
              rs_scan-writes_detected = abap_true.
              ls_hit-stmt_type = 'INSERT'. ls_hit-target = to_upper( lv_tab ). ls_hit-certainty = 'DEFINITE'.
              APPEND ls_hit TO rs_scan-findings.
            ENDIF.
          ENDIF.

          " --- UPDATE ---
          FIND REGEX '^\s*UPDATE\s*\(' IN lv_line IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-indeterminate = abap_true.
            ls_hit-stmt_type = 'UPDATE'. ls_hit-target = '(dynamic)'. ls_hit-certainty = 'INDETERMINATE'.
            APPEND ls_hit TO rs_scan-findings.
          ELSE.
            FIND REGEX `^\s*UPDATE\s+(\w+)\s+SET\b` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
            IF sy-subrc = 0.
              rs_scan-writes_detected = abap_true.
              ls_hit-stmt_type = 'UPDATE'. ls_hit-target = to_upper( lv_tab ). ls_hit-certainty = 'DEFINITE'.
              APPEND ls_hit TO rs_scan-findings.
            ENDIF.
          ENDIF.

          " --- DELETE ---
          FIND REGEX '^\s*DELETE\s*\(|^\s*DELETE\s+FROM\s+\(' IN lv_line IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-indeterminate = abap_true.
            ls_hit-stmt_type = 'DELETE'. ls_hit-target = '(dynamic)'. ls_hit-certainty = 'INDETERMINATE'.
            APPEND ls_hit TO rs_scan-findings.
          ELSE.
            FIND REGEX 'ADJACENT\s+DUPLICATES|^\s*DELETE\s+TABLE|INDEX|\bWHERE\b' IN lv_line IGNORING CASE.
            lv_itab = xsdbool( sy-subrc = 0 ).
            FIND REGEX `^\s*DELETE\s+FROM\s+(\w+)` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
            IF sy-subrc = 0.
              rs_scan-writes_detected = abap_true.
              ls_hit-stmt_type = 'DELETE'. ls_hit-target = to_upper( lv_tab ). ls_hit-certainty = 'DEFINITE'.
              APPEND ls_hit TO rs_scan-findings.
            ELSE.
              FIND REGEX `^\s*DELETE\s+(\w+)\s+FROM\s+\w+\s*\.` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
              IF sy-subrc = 0 AND lv_itab = abap_false.
                rs_scan-writes_detected = abap_true.
                ls_hit-stmt_type = 'DELETE'. ls_hit-target = to_upper( lv_tab ). ls_hit-certainty = 'DEFINITE'.
                APPEND ls_hit TO rs_scan-findings.
              ENDIF.
            ENDIF.
          ENDIF.

          " --- MODIFY ---
          FIND REGEX '^\s*MODIFY\s*\(' IN lv_line IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-indeterminate = abap_true.
            ls_hit-stmt_type = 'MODIFY'. ls_hit-target = '(dynamic)'. ls_hit-certainty = 'INDETERMINATE'.
            APPEND ls_hit TO rs_scan-findings.
          ELSE.
            FIND REGEX 'INDEX|TRANSPORTING|^\s*MODIFY\s+TABLE|^\s*MODIFY\s+LINE' IN lv_line IGNORING CASE.
            IF sy-subrc <> 0.
              FIND REGEX `^\s*MODIFY\s+(\w+)\s+FROM\s` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
              IF sy-subrc = 0.
                rs_scan-writes_detected = abap_true.
                ls_hit-stmt_type = 'MODIFY'. ls_hit-target = to_upper( lv_tab ). ls_hit-certainty = 'DEFINITE'.
                APPEND ls_hit TO rs_scan-findings.
              ENDIF.
            ENDIF.
          ENDIF.

          " --- COMMIT WORK / update task: the LUW is being posted ---
          FIND REGEX '\bCOMMIT\s+WORK\b' IN ls_src-masked IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-writes_detected = abap_true.
            ls_hit-stmt_type = 'COMMIT_WORK'. ls_hit-target = ''. ls_hit-certainty = 'DEFINITE'.
            APPEND ls_hit TO rs_scan-findings.
          ENDIF.
          FIND REGEX '\bIN\s+UPDATE\s+TASK\b' IN ls_src-masked IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-writes_detected = abap_true.
            ls_hit-stmt_type = 'UPDATE_TASK'. ls_hit-target = ''. ls_hit-certainty = 'DEFINITE'.
            APPEND ls_hit TO rs_scan-findings.
          ENDIF.

          " --- native SQL: statement text is not analysed ---
          FIND REGEX '\bEXEC\s+SQL\b|\bCL_SQL_STATEMENT\b' IN ls_src-masked IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-indeterminate = abap_true.
            ls_hit-stmt_type = 'NATIVE_SQL'. ls_hit-target = '(native)'. ls_hit-certainty = 'INDETERMINATE'.
            APPEND ls_hit TO rs_scan-findings.
          ENDIF.

          " --- CALL FUNCTION ---
          FIND REGEX `CALL\s+FUNCTION\s+'([\w/]+)'` IN lv_line IGNORING CASE SUBMATCHES lv_fm.
          IF sy-subrc = 0.
            lv_fm = to_upper( lv_fm ).
            IF is_known_updating_fm( lv_fm ) = abap_true.
              rs_scan-writes_detected = abap_true.
              ls_hit-stmt_type = 'CALL_FUNCTION_CURATED'. ls_hit-target = lv_fm. ls_hit-certainty = 'DEFINITE'.
              APPEND ls_hit TO rs_scan-findings.
            ELSE.
              FIND REGEX '_(CREATE|CHANGE|UPDATE|DELETE|INSERT|MODIFY|SAVE|POST|MAINTAIN|PUT|ACTIVATE|LOCK)\d*$' IN lv_fm.
              IF sy-subrc = 0.
                rs_scan-writes_detected = abap_true.
                ls_hit-stmt_type = 'CALL_FUNCTION_NAME_HEURISTIC'. ls_hit-target = lv_fm. ls_hit-certainty = 'DEFINITE'.
                APPEND ls_hit TO rs_scan-findings.
              ENDIF.
            ENDIF.
          ELSE.
            FIND REGEX '\bCALL\s+FUNCTION\b' IN ls_src-masked IGNORING CASE.
            IF sy-subrc = 0.
              rs_scan-indeterminate = abap_true.
              ls_hit-stmt_type = 'CALL_FUNCTION_DYNAMIC'. ls_hit-target = '(dynamic)'. ls_hit-certainty = 'INDETERMINATE'.
              APPEND ls_hit TO rs_scan-findings.
            ENDIF.
          ENDIF.

          " --- CALL TRANSACTION: the statement itself is the write risk ---
          FIND REGEX '\bCALL\s+TRANSACTION\b' IN ls_src-masked IGNORING CASE.
          IF sy-subrc = 0.
            CLEAR lv_tab.
            FIND REGEX `CALL\s+TRANSACTION\s+'(\w+)'` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
            rs_scan-writes_detected = abap_true.
            ls_hit-stmt_type = 'CALL_TRANSACTION'.
            ls_hit-target    = COND #( WHEN lv_tab IS INITIAL THEN '(dynamic target)' ELSE to_upper( lv_tab ) ).
            ls_hit-certainty = 'DEFINITE'.
            APPEND ls_hit TO rs_scan-findings.
          ENDIF.

          " --- SUBMIT: another program is a write signal, itself is not ---
          FIND REGEX '^\s*SUBMIT\s*\(' IN lv_line IGNORING CASE.
          IF sy-subrc = 0.
            rs_scan-indeterminate = abap_true.
            ls_hit-stmt_type = 'SUBMIT_DYNAMIC_TARGET'. ls_hit-target = '(dynamic)'. ls_hit-certainty = 'INDETERMINATE'.
            APPEND ls_hit TO rs_scan-findings.
          ELSE.
            FIND REGEX `^\s*SUBMIT\s+([\w/]+)` IN lv_line IGNORING CASE SUBMATCHES lv_tab.
            IF sy-subrc = 0.
              ls_hit-target    = to_upper( lv_tab ).
              ls_hit-certainty = 'DEFINITE'.
              IF ls_hit-target = ps_source-program.
                ls_hit-stmt_type = 'SUBMIT_SELF'.
              ELSE.
                ls_hit-stmt_type = 'SUBMIT_OTHER'.
                rs_scan-writes_detected = abap_true.
              ENDIF.
              APPEND ls_hit TO rs_scan-findings.
            ENDIF.
          ENDIF.
        ENDLOOP.
      CATCH cx_sy_regex_too_complex INTO DATA(lx_scan).
        " RR2: never "no writes" from a scan that stopped; B7 refuses on this finding.
        rs_scan-indeterminate = abap_true.
        APPEND VALUE #( incl = ls_src-incl line = ls_src-line stmt_type = 'REGEX_TOO_COMPLEX'
                        target = '(scan stopped)' certainty = 'INDETERMINATE'
                        src_line = lx_scan->get_text( ) ) TO rs_scan-findings.
    ENDTRY.

    rs_scan-scan_note = COND #(
      WHEN rs_scan-source_readable = abap_false THEN
        |READ REPORT failed for [{ ps_source-program }]; write capability is UNKNOWN, not "no writes found".|
      WHEN rs_scan-writes_detected = abap_true AND rs_scan-indeterminate = abap_true THEN
        `Write-capable statement(s) found AND dynamic/unexpandable construct(s) present; ` &&
        `the findings list may be incomplete.`
      WHEN rs_scan-writes_detected = abap_true THEN
        `Static write-capable statement(s) found (see findings).`
      WHEN rs_scan-indeterminate = abap_true THEN
        `No static write found, BUT dynamic/unexpandable construct(s) present; INDETERMINATE, never "read".`
      ELSE
        |No write-capable construct found in { rs_scan-source_lines_seen } code line(s) across the program | &&
        |and { rs_scan-includes_expanded } transitively expanded include(s).| ).
  ENDMETHOD.

  METHOD check_selection_coverage.
    check_coverage(
      EXPORTING ps_source         = read_source( pv_program )
                pt_selection      = pt_selection
      IMPORTING ev_ok             = ev_ok
                ev_missing_fields = ev_missing_fields ).
  ENDMETHOD.

  METHOD has_value.
    " A row of the wrong KIND is ignored by SUBMIT, so it supplies nothing.
    LOOP AT pt_selection TRANSPORTING NO FIELDS WHERE selname = pv_name AND kind = pv_kind AND low IS NOT INITIAL.
      rv_yes = abap_true.
      RETURN.
    ENDLOOP.
  ENDMETHOD.

  METHOD check_coverage.
    " Fails closed: an obligatory field with no non-empty LOW, a runtime
    " SCREEN-REQUIRED, an unexpandable source or an LDB screen that is not
    " fully supplied all refuse, because an unsatisfied selection screen
    " is the uncatchable abort.
    DATA lt_missing TYPE string_table.
    DATA lt_fields  TYPE ty_b7_selfields.
    DATA lv_known   TYPE abap_bool.
    DATA lv_reason  TYPE string.

    ev_ok = abap_true.
    CLEAR ev_missing_fields.

    IF ps_source-complete = abap_false.
      ev_ok             = abap_false.
      ev_missing_fields = |UNKNOWN (source of [{ ps_source-program }] could not be fully expanded)|.
      RETURN.
    ENDIF.

    TRY.
        DATA(lt_stmts) = statements( ps_source ).
        LOOP AT lt_stmts INTO DATA(ls_stmt).
          FIND REGEX 'SCREEN-REQUIRED\s*=\s*''?1' IN ls_stmt-code IGNORING CASE.
          IF sy-subrc = 0.
            ev_ok             = abap_false.
            ev_missing_fields = |UNKNOWN (SCREEN-REQUIRED set at runtime in [{ ls_stmt-incl }] line { ls_stmt-line })|.
            RETURN.
          ENDIF.
        ENDLOOP.
      CATCH cx_sy_regex_too_complex INTO DATA(lx_cov).
        " RR2: fail closed.
        ev_ok             = abap_false.
        ev_missing_fields = |UNKNOWN (selection-screen scan of [{ ps_source-program }] stopped: | &&
                            |{ lx_cov->get_text( ) })|.
        RETURN.
    ENDTRY.

    screen_fields( EXPORTING ps_source = ps_source
                   IMPORTING et_fields = lt_fields ev_known = lv_known ev_reason = lv_reason ).
    IF lv_known = abap_false.
      ev_ok             = abap_false.
      ev_missing_fields = |UNKNOWN ({ lv_reason })|.
      RETURN.
    ENDIF.
    " A program field counts when OBLIGATORY; an LDB screen must be fully supplied.
    LOOP AT lt_fields INTO DATA(ls_field) WHERE obligatory = abap_true OR ldb IS NOT INITIAL.
      IF has_value( pt_selection = pt_selection pv_name = ls_field-name pv_kind = ls_field-kind ) = abap_false.
        APPEND COND string( WHEN ls_field-ldb IS INITIAL THEN ls_field-name
                            ELSE |{ ls_field-name } (LDB { ls_field-ldb })| ) TO lt_missing.
      ENDIF.
    ENDLOOP.

    SORT lt_missing.
    DELETE ADJACENT DUPLICATES FROM lt_missing.
    IF lt_missing IS NOT INITIAL.
      ev_ok             = abap_false.
      ev_missing_fields = concat_lines_of( table = lt_missing sep = ', ' ).
    ENDIF.
  ENDMETHOD.

  METHOD capture.
    es_meta = ps_meta_in.
    CASE ps_meta_in-tier.
      WHEN 'A'.
        capture_tier_a(
          EXPORTING pv_program   = pv_program
                    pt_selection = pt_selection
                    pv_max_rows  = pv_max_rows
          IMPORTING et_fields    = et_fields
                    et_rows      = et_rows
          CHANGING  cs_meta      = es_meta ).
      WHEN 'B'.
        capture_tier_b(
          EXPORTING pv_program   = pv_program
                    pt_selection = pt_selection
                    pv_max_rows  = pv_max_rows
          IMPORTING et_fields    = et_fields
                    et_rows      = et_rows
          CHANGING  cs_meta      = es_meta ).
      WHEN OTHERS.
        refuse( EXPORTING pv_reason = |Internal: capture called for tier [{ ps_meta_in-tier }]; nothing submitted.|
                CHANGING cs_meta = es_meta ).
    ENDCASE.
  ENDMETHOD.

  METHOD capture_tier_a.
    DATA lr_data   TYPE REF TO data.
    DATA lx_error  TYPE REF TO cx_root.
    DATA lt_values TYPE string_table.
    DATA lv_row    TYPE string.
    DATA lv_bytes  TYPE int8.
    DATA lt_width  TYPE STANDARD TABLE OF i WITH EMPTY KEY.
    DATA lv_col    TYPE i.
    DATA lv_chars  TYPE i.
    FIELD-SYMBOLS <lt_data> TYPE ANY TABLE.

    cs_meta-delimiter = c_delimiter.

    " LIST TO MEMORY as well: an incidental WRITE in a SALV report would
    " otherwise try to display its list and abort.
    cl_salv_bs_runtime_info=>set( display = abap_false metadata = abap_false data = abap_true ).
    TRY.
        SUBMIT (pv_program) WITH SELECTION-TABLE pt_selection EXPORTING LIST TO MEMORY AND RETURN.
        cl_salv_bs_runtime_info=>get_data_ref( IMPORTING r_data = lr_data ).
      CATCH cx_root INTO lx_error.
    ENDTRY.
    cl_salv_bs_runtime_info=>clear_all( ).
    CALL FUNCTION 'LIST_FREE_MEMORY'.

    IF lx_error IS BOUND.
      " Named class: e.g. SALV's own capture of two >255 columns fails with
      " CX_SY_IMPORT_MISMATCH_ERROR, which must read as that, not a vague error.
      refuse( EXPORTING pv_reason = |Tier A: SUBMIT/get_data_ref raised | &&
                                    |{ cl_abap_classdescr=>get_class_name( lx_error ) }: { lx_error->get_text( ) }|
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.
    " No capture at all refuses. An empty captured table is still bound and
    " keeps its columns below: an empty report is not a capture failure.
    IF lr_data IS NOT BOUND.
      refuse( EXPORTING pv_reason = 'Tier A: SALV runtime-info returned no data (report produced no ALV output).'
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.

    ASSIGN lr_data->* TO <lt_data>.
    DATA(lo_table) = CAST cl_abap_tabledescr( cl_abap_typedescr=>describe_by_data( <lt_data> ) ).
    DATA(lo_line)  = lo_table->get_table_line_type( ).
    IF lo_line->kind <> cl_abap_typedescr=>kind_struct.
      refuse( EXPORTING pv_reason = 'Tier A: captured ALV line type is not a structure; cannot enumerate columns.'
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.
    DATA(lo_struct) = CAST cl_abap_structdescr( lo_line ).

    " Classic exceptions: a functional call cannot handle them and TRY does
    " not catch them, so a non-DDIC SALV line type dumped RAISE_EXCEPTION.
    DATA lt_ddic TYPE ddfields.
    CALL METHOD lo_struct->get_ddic_field_list
      RECEIVING  p_field_list = lt_ddic
      EXCEPTIONS not_found    = 1
                 no_ddic_type = 2
                 OTHERS       = 3.
    IF sy-subrc <> 0.
      CLEAR lt_ddic.
    ENDIF.

    " get_included_view flattens .INCLUDE/.APPEND groups; deep columns
    " (T_COLOR and the like) are reported, not stringified.
    DATA(lt_view) = lo_struct->get_included_view( ).
    DATA lt_elem LIKE lt_view.
    LOOP AT lt_view INTO DATA(ls_comp).
      IF ls_comp-type->kind <> cl_abap_typedescr=>kind_elem.
        cs_meta-skipped_columns = COND #( WHEN cs_meta-skipped_columns IS INITIAL THEN ls_comp-name
                                          ELSE |{ cs_meta-skipped_columns },{ ls_comp-name }| ).
        CONTINUE.
      ENDIF.
      APPEND ls_comp TO lt_elem.
      DATA(ls_ddic) = VALUE dfies( lt_ddic[ fieldname = ls_comp-name ] OPTIONAL ).
      " RTTI lengths of character-like types are bytes; LENGTH is characters.
      lv_chars = ls_comp-type->length.
      IF ls_comp-type->type_kind = cl_abap_typedescr=>typekind_char
         OR ls_comp-type->type_kind = cl_abap_typedescr=>typekind_num
         OR ls_comp-type->type_kind = cl_abap_typedescr=>typekind_date
         OR ls_comp-type->type_kind = cl_abap_typedescr=>typekind_time.
        lv_chars = ls_comp-type->length / cl_abap_char_utilities=>charsize.
      ENDIF.
      " A text column at SALV's 255-character capture width may hold cut
      " values unless DDIC proves it is no longer. The copy drops trailing
      " blanks, so a cut ending in a blank looks like a shorter whole value:
      " no per-value test is safe, and the column is flagged instead.
      APPEND COND i( WHEN ls_comp-type->type_kind = cl_abap_typedescr=>typekind_char AND lv_chars >= 255
                          AND NOT ( ls_ddic-leng IS NOT INITIAL AND ls_ddic-leng <= lv_chars )
                     THEN lv_chars ELSE 0 ) TO lt_width.
      APPEND VALUE #(
        position  = lines( lt_elem )
        fieldname = ls_comp-name
        rollname  = ls_ddic-rollname
        datatype  = COND #( WHEN ls_ddic-datatype IS NOT INITIAL THEN CONV string( ls_ddic-datatype )
                            ELSE |{ ls_comp-type->type_kind }| )
        length    = COND #( WHEN ls_ddic-leng IS NOT INITIAL THEN ls_ddic-leng ELSE lv_chars )
        decimals  = COND #( WHEN ls_ddic-decimals IS NOT INITIAL THEN ls_ddic-decimals ELSE ls_comp-type->decimals )
        note      = COND #( WHEN ls_ddic IS NOT INITIAL THEN `typed (DDIC)` ELSE `typed (ABAP RTTI only)` )
      ) TO et_fields.
    ENDLOOP.
    cs_meta-column_count = lines( et_fields ).

    LOOP AT <lt_data> ASSIGNING FIELD-SYMBOL(<ls_row>).
      IF lines( et_rows ) >= pv_max_rows.
        cs_meta-truncated = abap_true.
        EXIT.
      ENDIF.
      CLEAR lt_values.
      LOOP AT lt_elem INTO ls_comp.
        ASSIGN COMPONENT ls_comp-name OF STRUCTURE <ls_row> TO FIELD-SYMBOL(<lv_value>).
        IF sy-subrc = 0.
          " String templates format numbers with a leading minus.
          APPEND |{ <lv_value> }| TO lt_values.
        ELSE.
          APPEND `` TO lt_values.
        ENDIF.
      ENDLOOP.
      lv_row   = lcl_plaidcl_codec=>encode_row( lt_values ).
      lv_bytes = lv_bytes + 2 * strlen( lv_row ).
      IF lv_bytes > c_max_row_bytes.
        cs_meta-truncated = abap_true.
        EXIT.
      ENDIF.
      APPEND lv_row TO et_rows.
    ENDLOOP.

    " A column is never cut silently: flag it on the field and on the result,
    " for the rows actually returned.
    IF et_rows IS NOT INITIAL.
      LOOP AT lt_width INTO DATA(lv_width) WHERE table_line > 0.
        lv_col = sy-tabix.
        et_fields[ lv_col ]-note = |{ et_fields[ lv_col ]-note }; SALV capture keeps { lv_width } characters | &&
                                   |and the original column may be longer, so values may be cut|.
        cs_meta-truncated = abap_true.
      ENDLOOP.
    ENDIF.
    cs_meta-row_count = lines( et_rows ).
  ENDMETHOD.

  METHOD capture_tier_b.
    TYPES: BEGIN OF ty_list_line,
             text TYPE c LENGTH 1024,
           END OF ty_list_line.
    DATA lt_list     TYPE TABLE OF abaplist.
    DATA lt_ascii    TYPE STANDARD TABLE OF ty_list_line.
    DATA lt_split    TYPE STANDARD TABLE OF string_table.
    DATA lt_head     TYPE string_table.
    DATA lt_drop     TYPE SORTED TABLE OF i WITH UNIQUE KEY table_line.
    DATA lx_error    TYPE REF TO cx_root.
    DATA lv_cols     TYPE i.
    DATA lv_sep      TYPE i.
    DATA lv_hlen     TYPE i.
    DATA lv_at       TYPE i.
    DATA lv_k        TYPE i.
    DATA lv_idx      TYPE i.
    DATA lv_head_txt TYPE abap_bool.
    DATA lv_dropped  TYPE i.
    DATA lv_note     TYPE string.
    DATA lv_row      TYPE string.
    DATA lv_bytes    TYPE int8.
    DATA lv_kept     TYPE i.
    DATA lv_kept_cols TYPE i.

    cs_meta-delimiter = c_delimiter.

    TRY.
        SUBMIT (pv_program) WITH SELECTION-TABLE pt_selection EXPORTING LIST TO MEMORY AND RETURN.
      CATCH cx_root INTO lx_error.
    ENDTRY.
    CALL FUNCTION 'LIST_FROM_MEMORY'
      TABLES
        listobject = lt_list
      EXCEPTIONS
        not_found  = 1
        OTHERS     = 2.
    DATA(lv_from_rc) = sy-subrc.
    CALL FUNCTION 'LIST_FREE_MEMORY'.

    IF lx_error IS BOUND.
      refuse( EXPORTING pv_reason = |Tier B: SUBMIT raised | &&
                                    |{ cl_abap_classdescr=>get_class_name( lx_error ) }: { lx_error->get_text( ) }|
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.
    IF lv_from_rc <> 0 OR lt_list IS INITIAL.
      refuse( EXPORTING pv_reason = |Tier B: LIST_FROM_MEMORY found no list (subrc={ lv_from_rc }).|
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.

    " RN1: LIST_TO_ASCI expands the whole compressed list into 2 KB lines in
    " one call. Refuse an oversized list before that, so it can't exhaust
    " extended memory (the ~1.4 GB trial limit); the SUBMIT already returned.
    IF lines( lt_list ) > c_max_list_chunks.
      FREE lt_list.
      refuse( EXPORTING pv_reason = |Tier B: list has { lines( lt_list ) } compressed chunks, over the | &&
                                    |{ c_max_list_chunks }-chunk budget; refused before LIST_TO_ASCI to | &&
                                    |avoid exhausting extended memory. Narrow the selection.|
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.

    CALL FUNCTION 'LIST_TO_ASCI'
      TABLES
        listasci   = lt_ascii
        listobject = lt_list
      EXCEPTIONS
        OTHERS     = 1.
    DATA(lv_asci_rc) = sy-subrc.
    FREE lt_list.
    IF lv_asci_rc <> 0.
      refuse( EXPORTING pv_reason = |Tier B: LIST_TO_ASCI failed (subrc={ lv_asci_rc }).|
              CHANGING cs_meta = cs_meta ).
      RETURN.
    ENDIF.

    " DB1: a list line is dropped as page heading only when that is proven.
    " H = the lines above the first rule line, if it lies within
    " c_max_heading_lines. H is proven heading when the report keeps SAP's
    " standard page heading (title, column headers, ULINE -- always first),
    " or when all of H, digits masked, recurs later as one contiguous run (a
    " TOP-OF-PAGE repeat at a page break); every such run is dropped too. An
    " H that never recurs is data, e.g. NO STANDARD PAGE HEADING rows above a
    " ULINE, and is kept.
    LOOP AT lt_ascii INTO DATA(ls_scan).
      lv_idx = sy-tabix.
      IF lv_idx > c_max_heading_lines.
        EXIT.
      ENDIF.
      IF is_separator( CONV string( ls_scan-text ) ) = abap_true.
        lv_sep = lv_idx.
        EXIT.
      ENDIF.
      APPEND mask_digits( CONV string( ls_scan-text ) ) TO lt_head.
      IF ls_scan-text CN ' '.
        lv_head_txt = abap_true.
      ENDIF.
    ENDLOOP.

    IF lv_sep > 1 AND lv_head_txt = abap_true.
      lv_hlen = lines( lt_head ).
      lv_at   = lv_sep + 1.
      WHILE lv_at + lv_hlen - 1 <= lines( lt_ascii ).
        lv_k = 0.
        WHILE lv_k < lv_hlen.
          lv_idx = lv_at + lv_k.
          lv_k   = lv_k + 1.
          IF mask_digits( CONV string( lt_ascii[ lv_idx ]-text ) ) <> lt_head[ lv_k ].
            lv_k = -1.
            EXIT.
          ENDIF.
        ENDWHILE.
        IF lv_k = lv_hlen.
          DO lv_hlen TIMES.
            lv_idx = lv_at + sy-index - 1.
            INSERT lv_idx INTO TABLE lt_drop.
          ENDDO.
          lv_at = lv_at + lv_hlen.
        ELSE.
          lv_at = lv_at + 1.
        ENDIF.
      ENDWHILE.
      IF cs_meta-std_heading = abap_true OR lt_drop IS NOT INITIAL.
        DO lv_hlen TIMES.
          lv_idx = sy-index.
          INSERT lv_idx INTO TABLE lt_drop.
        ENDDO.
      ENDIF.
    ENDIF.

    LOOP AT lt_ascii INTO DATA(ls_line).
      lv_idx = sy-tabix.
      DATA(lv_text) = CONV string( ls_line-text ).
      " Rule lines and proven page headings are not data rows and don't count
      " toward max_rows.
      IF is_separator( lv_text ) = abap_true.
        CONTINUE.
      ENDIF.
      IF line_exists( lt_drop[ table_line = lv_idx ] ).
        IF lv_text IS NOT INITIAL.
          lv_dropped = lv_dropped + 1.
        ENDIF.
        CONTINUE.
      ENDIF.
      DATA(lt_cols) = split_columns( lv_text ).
      IF lt_cols IS INITIAL.
        CONTINUE.
      ENDIF.
      IF lines( lt_split ) >= pv_max_rows.
        cs_meta-truncated = abap_true.
        EXIT.
      ENDIF.
      APPEND lt_cols TO lt_split.
      IF lines( lt_cols ) > lv_cols.
        lv_cols = lines( lt_cols ).
      ENDIF.
    ENDLOOP.
    FREE lt_ascii.

    LOOP AT lt_split INTO lt_cols.
      lv_row   = encode_positional( pt_cols = lt_cols pv_cols = lv_cols ).
      lv_bytes = lv_bytes + 2 * strlen( lv_row ).
      IF lv_bytes > c_max_row_bytes.
        cs_meta-truncated = abap_true.
        EXIT.
      ENDIF.
      APPEND lv_row TO et_rows.
      IF lines( lt_cols ) > lv_kept_cols.
        lv_kept_cols = lines( lt_cols ).
      ENDIF.
    ENDLOOP.
    " The column count is the widest KEPT row: rows the byte budget dropped
    " must not add trailing empty columns. Narrower rows re-encode smaller,
    " so the budget still holds.
    IF lv_kept_cols < lv_cols.
      lv_kept = lines( et_rows ).
      CLEAR et_rows.
      LOOP AT lt_split INTO lt_cols TO lv_kept.
        APPEND encode_positional( pt_cols = lt_cols pv_cols = lv_kept_cols ) TO et_rows.
      ENDLOOP.
      lv_cols = lv_kept_cols.
    ENDIF.

    " A dropped heading is reported, never silent. A drop proven only by a
    " repeat (no standard heading) can be mimicked by rows, so it also sets
    " EV_TRUNCATED: with every line dropped there is no field to carry the
    " NOTE, and the B12 -> B8 path squeezes NOTEs.
    lv_note = `positional (classic list capture); no DDIC type available`.
    IF lv_dropped > 0.
      lv_note = |{ lv_note }; { lv_dropped } list line(s) dropped as page heading|.
      IF cs_meta-std_heading = abap_false.
        cs_meta-truncated = abap_true.
      ENDIF.
    ENDIF.
    DO lv_cols TIMES.
      APPEND VALUE #( position  = sy-index
                      fieldname = |COL{ sy-index }|
                      datatype  = 'POSITIONAL'
                      note      = lv_note ) TO et_fields.
    ENDDO.
    cs_meta-column_count = lv_cols.
    cs_meta-row_count    = lines( et_rows ).
  ENDMETHOD.

  METHOD encode_positional.
    DATA lt_values TYPE string_table.
    DATA lv_tlen   TYPE i.
    DO pv_cols TIMES.
      DATA(lv_txt) = COND string( WHEN sy-index <= lines( pt_cols ) THEN pt_cols[ sy-index ] ELSE `` ).
      " List output prints negatives as 1,000.00-; the wire uses a leading minus.
      lv_tlen = strlen( lv_txt ).
      IF lv_tlen > 1.
        IF substring( val = lv_txt off = lv_tlen - 1 ) = `-`
           AND substring( val = lv_txt len = 1 ) CO '0123456789'
           AND substring( val = lv_txt len = lv_tlen - 1 ) CO '0123456789.,'.
          lv_txt = |-{ substring( val = lv_txt len = lv_tlen - 1 ) }|.
        ENDIF.
      ENDIF.
      APPEND lv_txt TO lt_values.
    ENDDO.
    rv_row = lcl_plaidcl_codec=>encode_row( lt_values ).
  ENDMETHOD.

  METHOD split_columns.
    " Heuristic: a run of >= 2 spaces is a column boundary; a single space
    " stays inside the value. SPLIT, not a regex, so no engine limit applies.
    SPLIT pv_line AT `  ` INTO TABLE DATA(lt_parts).
    LOOP AT lt_parts INTO DATA(lv_part).
      SHIFT lv_part LEFT DELETING LEADING ` `.
      IF lv_part IS NOT INITIAL.
        APPEND lv_part TO rt_cols.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD screen_fields.
    DATA lv_ldb  TYPE trdir-ldbname.
    DATA lv_ns   TYPE string.
    DATA lv_base TYPE string.
    DATA lv_sel  TYPE programm.
    DATA lx_scan TYPE REF TO cx_root.

    CLEAR: et_fields, ev_reason.
    ev_known = abap_false.
    IF ps_source-complete = abap_false.
      ev_reason = |source of [{ ps_source-program }] could not be fully expanded|.
      RETURN.
    ENDIF.

    TRY.
        et_fields = selection_fields( statements( ps_source ) ).

        SELECT SINGLE ldbname FROM trdir INTO lv_ldb WHERE name = ps_source-program.
        IF lv_ldb IS NOT INITIAL.
          FIND REGEX '^(/\w+/)(.+)$' IN lv_ldb SUBMATCHES lv_ns lv_base.
          IF sy-subrc <> 0.
            CLEAR lv_ns.
            lv_base = lv_ldb.
          ENDIF.
          " The LDB selection include is DB<ldb>SEL (SAPDB<ldb> is the database
          " program). Placeholder LDBs such as D$S / __S have an empty one.
          lv_sel = |{ lv_ns }DB{ condense( lv_base ) }SEL|.
          DATA(ls_ldb_source) = read_source( lv_sel ).
          IF ls_ldb_source-denied = abap_true.
            CLEAR et_fields.
            ev_reason = ls_ldb_source-denied_reason.
            RETURN.
          ENDIF.
          IF ls_ldb_source-complete = abap_false.
            CLEAR et_fields.
            ev_reason = |logical database [{ lv_ldb }] selection include [{ lv_sel }] unreadable|.
            RETURN.
          ENDIF.
          DATA(lt_ldb_fields) = selection_fields( statements( ls_ldb_source ) ).
          LOOP AT lt_ldb_fields INTO DATA(ls_ldb_field).
            ls_ldb_field-ldb = lv_ldb.
            APPEND ls_ldb_field TO et_fields.
          ENDLOOP.
        ENDIF.
      CATCH cx_sy_regex_too_complex cx_sy_no_handler INTO lx_scan.
        " RR2: fail closed. selection_fields has no RAISING clause, so its limit
        " arrives wrapped as CX_SY_NO_HANDLER.
        CLEAR et_fields.
        ev_reason = |selection-screen scan of [{ ps_source-program }] stopped: { lx_scan->get_text( ) }|.
        RETURN.
    ENDTRY.
    ev_known = abap_true.
  ENDMETHOD.

  METHOD check_selnames.
    DATA lt_fields TYPE ty_b7_selfields.
    DATA lt_names  TYPE string_table.
    DATA lv_known  TYPE abap_bool.
    DATA lv_reason TYPE string.
    DATA lv_name   TYPE string.
    DATA ls_found  TYPE ty_b7_selfield.

    ev_ok = abap_true.
    CLEAR ev_error.
    IF pt_selection IS INITIAL.
      RETURN.
    ENDIF.

    screen_fields( EXPORTING ps_source = ps_source
                   IMPORTING et_fields = lt_fields ev_known = lv_known ev_reason = lv_reason ).
    IF lv_known = abap_false.
      ev_ok    = abap_false.
      ev_error = |IT_SELECTION refused: the selection screen of [{ ps_source-program }] can't be determined | &&
                 |({ lv_reason }), so SUBMIT could silently ignore a row.|.
      RETURN.
    ENDIF.

    LOOP AT pt_selection INTO DATA(ls_sel).
      DATA(lv_row_no) = sy-tabix.
      lv_name = ls_sel-selname.
      IF NOT line_exists( lt_fields[ name = lv_name ] ).
        LOOP AT lt_fields INTO DATA(ls_field).
          APPEND ls_field-name TO lt_names.
        ENDLOOP.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no }: [{ lv_name }] is not a selection field of | &&
                   |[{ ps_source-program }]; SUBMIT would ignore it. Fields: | &&
                   |{ COND string( WHEN lt_names IS INITIAL THEN `none`
                                   ELSE concat_lines_of( table = lt_names sep = `, ` ) ) }.|.
        RETURN.
      ENDIF.
      " SUBMIT also ignores a row whose KIND doesn't match the field (as B6 refuses).
      ls_found = lt_fields[ name = lv_name ].
      IF ls_found-kind <> ls_sel-kind.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no }: [{ lv_name }] is | &&
                   |{ COND string( WHEN ls_found-kind = 'P' THEN `PARAMETERS (KIND P)` ELSE `SELECT-OPTIONS (KIND S)` ) } | &&
                   |but the row has KIND { ls_sel-kind }; SUBMIT would ignore it.|.
        RETURN.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD decode_selection.
    " N3: KIND/SIGN/OPTION go straight into RSPARAMS, so an out-of-range value
    " would reach SUBMIT unchecked. Allowlist them; BT/NB need a HIGH bound.
    DATA(lt_opts) = VALUE string_table(
      ( `EQ` ) ( `NE` ) ( `BT` ) ( `NB` ) ( `CP` ) ( `NP` ) ( `GT` ) ( `GE` ) ( `LT` ) ( `LE` ) ).
    ev_ok = abap_true.
    CLEAR: et_sel, ev_error.
    LOOP AT pt_wire INTO DATA(lv_line).
      DATA(lv_row_no) = sy-tabix.
      DATA(lt_parts)  = lcl_plaidcl_codec=>decode_row( lv_line ).
      IF lines( lt_parts ) <> 6.
        ev_ok    = abap_false.
        ev_error = |Malformed IT_SELECTION entry { lv_row_no }: expected 6 codec fields | &&
                   |(SELNAME, KIND, SIGN, OPTION, LOW, HIGH), found { lines( lt_parts ) }.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      " Screen field names are upper case; RSPARAMS holds SELNAME C8 and
      " LOW/HIGH C45 and would cut a longer value silently.
      DATA(lv_name)   = to_upper( lt_parts[ 1 ] ).
      DATA(lv_kind)   = to_upper( lt_parts[ 2 ] ).
      DATA(lv_sign)   = to_upper( lt_parts[ 3 ] ).
      DATA(lv_option) = to_upper( lt_parts[ 4 ] ).
      IF strlen( lv_name ) > 8.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no }: SELNAME [{ lv_name }] is { strlen( lv_name ) } characters; | &&
                   |RSPARAMS holds at most 8.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      IF strlen( lt_parts[ 5 ] ) > 45 OR strlen( lt_parts[ 6 ] ) > 45.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no } ([{ lv_name }]): LOW/HIGH is longer than 45 characters; | &&
                   |RSPARAMS would cut it.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      IF lv_kind <> 'P' AND lv_kind <> 'S'.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no } ([{ lv_name }]): KIND [{ lt_parts[ 2 ] }] must be 'P' or 'S'.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      IF lv_sign <> 'I' AND lv_sign <> 'E'.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no } ([{ lv_name }]): SIGN [{ lt_parts[ 3 ] }] must be 'I' or 'E'.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      IF NOT line_exists( lt_opts[ table_line = lv_option ] ).
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no } ([{ lv_name }]): OPTION [{ lt_parts[ 4 ] }] is not one of | &&
                   |EQ NE BT NB CP NP GT GE LT LE.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      IF ( lv_option = 'BT' OR lv_option = 'NB' ) AND lt_parts[ 6 ] IS INITIAL.
        ev_ok    = abap_false.
        ev_error = |IT_SELECTION entry { lv_row_no } ([{ lv_name }]): OPTION [{ lv_option }] requires a HIGH value.|.
        CLEAR et_sel.
        RETURN.
      ENDIF.
      APPEND VALUE #( selname = lv_name
                      kind    = lv_kind
                      sign    = lv_sign
                      option  = lv_option
                      low     = lt_parts[ 5 ]
                      high    = lt_parts[ 6 ] ) TO et_sel.
    ENDLOOP.
  ENDMETHOD.

  METHOD encode_fields.
    LOOP AT pt_fields INTO DATA(ls_field).
      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ ls_field-position }| ) ( |{ ls_field-fieldname }| ) ( |{ ls_field-rollname }| ) ( |{ ls_field-datatype }| )
        ( |{ ls_field-length }| ) ( |{ ls_field-decimals }| ) ( |{ ls_field-note }| ) ) ) TO rt_wire.
    ENDLOOP.
  ENDMETHOD.

  METHOD flatten_meta.
    ev_tier            = ps_meta-tier.
    ev_tier_label      = ps_meta-tier_label.
    ev_program         = ps_meta-program.
    ev_tcode           = ps_meta-tcode.
    ev_refused         = ps_meta-refused.
    ev_refusal_reason  = ps_meta-refusal_reason.
    ev_row_count       = ps_meta-row_count.
    ev_column_count    = ps_meta-column_count.
    ev_truncated       = ps_meta-truncated.
    ev_delimiter       = ps_meta-delimiter.
    ev_skipped_columns = ps_meta-skipped_columns.
  ENDMETHOD.

  METHOD message_chunks.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = pv_text
                                   IMPORTING ev_v1 = ev_v1 ev_v2 = ev_v2 ev_v3 = ev_v3 ev_v4 = ev_v4 ).
  ENDMETHOD.

  METHOD worker_body.
    DATA lt_sel     TYPE ty_b7_seltab.
    DATA lv_sel_ok  TYPE abap_bool.
    DATA lv_missing TYPE string.
    DATA lv_exists  TYPE trdir-name.
    DATA lt_fields  TYPE ty_b7_fields.

    CLEAR: es_meta, et_fields, et_rows, ev_error, ev_error_text.

    IF pv_program IS INITIAL OR pv_max_rows < 1.
      ev_error      = c_err_invalid_input.
      ev_error_text = `Capture worker: IV_PROGRAM is required and IV_MAX_ROWS must be at least 1.`.
      RETURN.
    ENDIF.
    " CT4: the same key B7 raises for the same input.
    IF pv_max_rows > c_max_rows.
      ev_error      = c_err_max_rows.
      ev_error_text = |IV_MAX_ROWS { pv_max_rows } exceeds the maximum { c_max_rows }.|.
      RETURN.
    ENDIF.

    decode_selection(
      EXPORTING pt_wire  = pt_wire_sel
      IMPORTING et_sel   = lt_sel
                ev_ok    = lv_sel_ok
                ev_error = ev_error_text ).
    IF lv_sel_ok = abap_false.
      ev_error = c_err_invalid_input.
      RETURN.
    ENDIF.

    SELECT SINGLE name FROM trdir INTO lv_exists WHERE name = pv_program.
    IF sy-subrc <> 0.
      ev_error      = c_err_not_found.
      ev_error_text = |Program [{ pv_program }] not found in TRDIR.|.
      RETURN.
    ENDIF.

    " Contract 1, repeated here: the worker FM is itself RFC-callable.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
      EXPORTING
        iv_program        = pv_program
        iv_tcode          = pv_tcode
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
    CASE sy-subrc.
      WHEN 0.
      WHEN 2.
        ev_error      = c_err_not_found.
        ev_error_text = |Program [{ pv_program }] not found (worker gate).|.
        RETURN.
      WHEN OTHERS.
        ev_error      = c_err_not_authorized.
        ev_error_text = |Not authorized to run program [{ pv_program }] (worker gate).|.
        RETURN.
    ENDCASE.

    " Source gate (S_DEVELOP) is inside read_source.
    DATA(ls_source) = read_source( pv_program ).
    IF ls_source-denied = abap_true.
      ev_error      = c_err_not_authorized.
      ev_error_text = ls_source-denied_reason.
      RETURN.
    ENDIF.

    " An unknown SELNAME would be ignored by SUBMIT: the run would be unfiltered.
    check_selnames( EXPORTING ps_source    = ls_source
                              pt_selection = lt_sel
                    IMPORTING ev_ok        = lv_sel_ok
                              ev_error     = ev_error_text ).
    IF lv_sel_ok = abap_false.
      ev_error = c_err_invalid_input.
      RETURN.
    ENDIF.

    es_meta       = classify_source( ls_source ).
    es_meta-tcode = pv_tcode.

    " RR2, same as B7: a write scan stopped by the regex limit can't vouch for
    " the source. Repeated here because the worker FM is RFC-callable.
    IF es_meta-refused = abap_false.
      DATA(ls_writes) = scan_writes( ls_source ).
      IF line_exists( ls_writes-findings[ stmt_type = `REGEX_TOO_COMPLEX` ] ).
        refuse( EXPORTING pv_reason = |Refused: the write-capability scan of [{ pv_program }] hit the regex | &&
                                      |engine's complexity limit, so the source was not fully analysed.|
                CHANGING cs_meta = es_meta ).
      ENDIF.
    ENDIF.

    IF es_meta-refused = abap_false.
      check_coverage(
        EXPORTING ps_source         = ls_source
                  pt_selection      = lt_sel
        IMPORTING ev_ok             = lv_sel_ok
                  ev_missing_fields = lv_missing ).
      IF lv_sel_ok = abap_false.
        refuse( EXPORTING pv_reason = |Refused: obligatory selection field(s) not supplied with a value: [{ lv_missing }].|
                CHANGING cs_meta = es_meta ).
      ENDIF.
    ENDIF.

    IF es_meta-refused = abap_false.
      capture(
        EXPORTING pv_program   = pv_program
                  ps_meta_in   = es_meta
                  pt_selection = lt_sel
                  pv_max_rows  = pv_max_rows
        IMPORTING es_meta      = es_meta
                  et_fields    = lt_fields
                  et_rows      = et_rows ).
      et_fields = encode_fields( lt_fields ).
    ENDIF.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B7_RUN_TCODE -- remote-enabled, group Z_PLAIDCL.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b7_run_tcode.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_REPORT) TYPE  PROGRAMM OPTIONAL
*"     VALUE(IV_MAX_ROWS) TYPE  I DEFAULT 10000
*"     VALUE(IT_SELECTION) TYPE  STRING_TABLE OPTIONAL
*"  EXPORTING
*"     VALUE(EV_TIER) TYPE  STRING
*"     VALUE(EV_TIER_LABEL) TYPE  STRING
*"     VALUE(EV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(EV_TCODE) TYPE  TCODE
*"     VALUE(EV_REFUSED) TYPE  BOOLE_D
*"     VALUE(EV_REFUSAL_REASON) TYPE  STRING
*"     VALUE(EV_ROW_COUNT) TYPE  I
*"     VALUE(EV_COLUMN_COUNT) TYPE  I
*"     VALUE(EV_TRUNCATED) TYPE  BOOLE_D
*"     VALUE(EV_DELIMITER) TYPE  STRING
*"     VALUE(EV_SKIPPED_COLUMNS) TYPE  STRING
*"     VALUE(EV_WRITES_DETECTED) TYPE  BOOLE_D
*"     VALUE(EV_INDETERMINATE) TYPE  BOOLE_D
*"     VALUE(ET_FIELDS) TYPE  STRING_TABLE
*"     VALUE(ET_ROWS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      NOT_AUTHORIZED
*"      MAX_ROWS_EXCEEDED
*"      CAPTURE_ABORTED
*"----------------------------------------------------------------------



  DATA lv_v1      TYPE symsgv.
  DATA lv_v2      TYPE symsgv.
  DATA lv_v3      TYPE symsgv.
  DATA lv_v4      TYPE symsgv.
  DATA lt_sel     TYPE ty_b7_seltab.
  DATA lv_sel_ok  TYPE abap_bool.
  DATA lv_err     TYPE string.
  DATA lv_program TYPE programm.
  DATA ls_meta    TYPE ty_b7_meta.
  DATA lv_pgmna   TYPE tstc-pgmna.
  DATA lv_exists  TYPE trdir-name.
  DATA lv_missing TYPE string.

  CLEAR: ev_tier, ev_tier_label, ev_program, ev_tcode, ev_refused, ev_refusal_reason,
         ev_row_count, ev_column_count, ev_truncated, ev_delimiter, ev_skipped_columns,
         ev_writes_detected, ev_indeterminate, et_fields, et_rows.

  IF ( iv_tcode IS INITIAL AND iv_report IS INITIAL )
     OR ( iv_tcode IS NOT INITIAL AND iv_report IS NOT INITIAL ).
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = `Supply exactly one of IV_TCODE / IV_REPORT.`
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  IF iv_max_rows < 1.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = |IV_MAX_ROWS must be at least 1, got { iv_max_rows }.|
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.
  IF iv_max_rows > lcl_b7_tcode_capture=>c_max_rows.
    lcl_b7_tcode_capture=>message_chunks(
      EXPORTING pv_text = |IV_MAX_ROWS { iv_max_rows } exceeds the maximum { lcl_b7_tcode_capture=>c_max_rows }.|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING max_rows_exceeded.
  ENDIF.

  lcl_b7_tcode_capture=>decode_selection(
    EXPORTING pt_wire  = it_selection
    IMPORTING et_sel   = lt_sel
              ev_ok    = lv_sel_ok
              ev_error = lv_err ).
  IF lv_sel_ok = abap_false.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = lv_err
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  IF iv_report IS NOT INITIAL.
    lv_program = iv_report.
  ELSE.
    " Classic report transactions only; parameter/OO transactions refuse.
    SELECT SINGLE pgmna FROM tstc INTO lv_pgmna WHERE tcode = iv_tcode.
    IF sy-subrc <> 0.
      lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = |Transaction [{ iv_tcode }] not found in TSTC.|
                                            IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
    ENDIF.
    IF lv_pgmna IS INITIAL.
      ls_meta-tcode          = iv_tcode.
      ls_meta-tier           = 'C'.
      ls_meta-tier_label     = 'REFUSED'.
      ls_meta-refused        = abap_true.
      ls_meta-refusal_reason = |Refused: transaction [{ iv_tcode }] has no TSTC-PGMNA (parameter/OO transaction).|.
      lcl_b7_tcode_capture=>flatten_meta(
        EXPORTING ps_meta            = ls_meta
        IMPORTING ev_tier            = ev_tier
                  ev_tier_label      = ev_tier_label
                  ev_program         = ev_program
                  ev_tcode           = ev_tcode
                  ev_refused         = ev_refused
                  ev_refusal_reason  = ev_refusal_reason
                  ev_row_count       = ev_row_count
                  ev_column_count    = ev_column_count
                  ev_truncated       = ev_truncated
                  ev_delimiter       = ev_delimiter
                  ev_skipped_columns = ev_skipped_columns ).
      ev_indeterminate = abap_true.
      RETURN.
    ENDIF.
    lv_program = lv_pgmna.
  ENDIF.

  SELECT SINGLE name FROM trdir INTO lv_exists WHERE name = lv_program.
  IF sy-subrc <> 0.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = |Program [{ lv_program }] not found in TRDIR.|
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.

  " Contract 1: SAP's own S_TCODE / S_PROGRAM before any source read or SUBMIT.
  CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
    EXPORTING
      iv_program        = lv_program
      iv_tcode          = iv_tcode
    EXCEPTIONS
      not_authorized    = 1
      program_not_found = 2
      OTHERS            = 3.
  CASE sy-subrc.
    WHEN 0.
    WHEN 2.
      lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = |Program [{ lv_program }] not found (authorization gate).|
                                            IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
    WHEN OTHERS.
      lcl_b7_tcode_capture=>message_chunks(
        EXPORTING pv_text = |Not authorized to run program [{ lv_program }] (tcode [{ iv_tcode }]).|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
  ENDCASE.

  DATA(ls_source) = lcl_b7_tcode_capture=>read_source( lv_program ).
  IF ls_source-denied = abap_true.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = ls_source-denied_reason
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
  ENDIF.
  " An unknown SELNAME would be ignored by SUBMIT: the run would be unfiltered.
  lcl_b7_tcode_capture=>check_selnames( EXPORTING ps_source    = ls_source
                                                  pt_selection = lt_sel
                                        IMPORTING ev_ok        = lv_sel_ok
                                                  ev_error     = lv_err ).
  IF lv_sel_ok = abap_false.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = lv_err
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.
  DATA(ls_writes) = lcl_b7_tcode_capture=>scan_writes( ls_source ).
  ev_writes_detected = ls_writes-writes_detected.
  ev_indeterminate   = ls_writes-indeterminate.

  ls_meta       = lcl_b7_tcode_capture=>classify_source( ls_source ).
  ls_meta-tcode = iv_tcode.
  " RR2: a write scan stopped by the regex engine limit can't vouch for the source.
  IF ls_meta-refused = abap_false AND line_exists( ls_writes-findings[ stmt_type = `REGEX_TOO_COMPLEX` ] ).
    ls_meta-tier           = 'C'.
    ls_meta-tier_label     = 'REFUSED'.
    ls_meta-refused        = abap_true.
    ls_meta-refusal_reason = |Refused: the write-capability scan of [{ lv_program }] hit the regex engine's | &&
                             |complexity limit, so the source was not fully analysed.|.
  ENDIF.

  IF ls_meta-refused = abap_false.
    lcl_b7_tcode_capture=>check_coverage(
      EXPORTING ps_source         = ls_source
                pt_selection      = lt_sel
      IMPORTING ev_ok             = lv_sel_ok
                ev_missing_fields = lv_missing ).
    IF lv_sel_ok = abap_false.
      ls_meta-tier           = 'C'.
      ls_meta-tier_label     = 'REFUSED'.
      ls_meta-refused        = abap_true.
      ls_meta-refusal_reason = |Refused: obligatory selection field(s) not supplied with a value: [{ lv_missing }].|.
    ENDIF.
  ENDIF.

  IF ls_meta-refused = abap_false AND sy-batch = 'X'.
    " RB1: inside a background job (B12) the job is the isolation boundary --
    " an abort cancels it (TBTCO A -> RUN_FAILED). A NONE hop from here would
    " run the report in a DIALOG work process: cut at the dialog runtime
    " limit, out of CANCEL's reach, and holding a second work process. So the
    " worker body, gates included, runs in this process.
    DATA ls_bmeta TYPE ty_b7_meta.
    DATA lv_berr  TYPE i.
    DATA lv_btext TYPE string.
    lcl_b7_tcode_capture=>worker_body(
      EXPORTING pv_program    = lv_program
                pv_tcode      = iv_tcode
                pv_max_rows   = iv_max_rows
                pt_wire_sel   = it_selection
      IMPORTING es_meta       = ls_bmeta
                et_fields     = et_fields
                et_rows       = et_rows
                ev_error      = lv_berr
                ev_error_text = lv_btext ).
    IF lv_berr <> 0.
      lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = lv_btext
                                            IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      CASE lv_berr.
        WHEN lcl_b7_tcode_capture=>c_err_not_found.
          MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
        WHEN lcl_b7_tcode_capture=>c_err_not_authorized.
          MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
        WHEN lcl_b7_tcode_capture=>c_err_max_rows.
          MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING max_rows_exceeded.
        WHEN OTHERS.
          MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
      ENDCASE.
    ENDIF.
    ls_meta = ls_bmeta.
    IF ls_meta-refused = abap_true.
      CLEAR: et_fields, et_rows.
    ENDIF.
  ELSEIF ls_meta-refused = abap_false.
    " Isolation (addendum D): the SUBMIT runs in a private loopback session via
    " DESTINATION 'NONE', so an uncatchable DYNPRO_SEND_IN_BACKGROUND / MESSAGE
    " abort in the target report kills only that session and comes back as
    " SYSTEM_FAILURE -> CAPTURE_ABORTED (text carried). The connection is closed
    " after the call so the report's ABAP/SET PARAMETER memory cannot leak.
    DATA lv_msg     TYPE c LENGTH 200.
    DATA lv_wtier   TYPE string.
    DATA lv_wlabel  TYPE string.
    DATA lv_wref    TYPE boole_d.
    DATA lv_wreason TYPE string.
    CALL FUNCTION 'Z_PLAIDCL_B7_CAPTURE_WORKER' DESTINATION 'NONE'
      EXPORTING
        iv_program            = lv_program
        iv_tcode              = iv_tcode
        iv_max_rows           = iv_max_rows
        it_selection          = it_selection
      IMPORTING
        ev_tier               = lv_wtier
        ev_tier_label         = lv_wlabel
        ev_refused            = lv_wref
        ev_refusal_reason     = lv_wreason
        ev_row_count          = ls_meta-row_count
        ev_column_count       = ls_meta-column_count
        ev_truncated          = ls_meta-truncated
        ev_skipped_columns    = ls_meta-skipped_columns
        et_fields             = et_fields
        et_rows               = et_rows
      EXCEPTIONS
        invalid_input         = 1
        not_found             = 2
        not_authorized        = 3
        max_rows_exceeded     = 4
        system_failure        = 5 MESSAGE lv_msg
        communication_failure = 6 MESSAGE lv_msg
        OTHERS                = 7.
    DATA(lv_wrc) = sy-subrc.
    " A named worker exception carries the worker's own text (the gate's reason) in sy-msgv.
    lv_v1 = sy-msgv1.
    lv_v2 = sy-msgv2.
    lv_v3 = sy-msgv3.
    lv_v4 = sy-msgv4.
    CALL FUNCTION 'RFC_CONNECTION_CLOSE'
      EXPORTING  destination = 'NONE'
      EXCEPTIONS OTHERS      = 0.
    CASE lv_wrc.
      WHEN 0.
        IF lv_wref = abap_true.
          ls_meta-tier           = lv_wtier.
          ls_meta-tier_label     = lv_wlabel.
          ls_meta-refused        = abap_true.
          ls_meta-refusal_reason = lv_wreason.
          CLEAR: et_fields, et_rows.
        ENDIF.
      WHEN 1.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
      WHEN 2.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
      WHEN 3.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
      WHEN 4.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING max_rows_exceeded.
      WHEN OTHERS.
        lcl_b7_tcode_capture=>message_chunks(
          EXPORTING pv_text = |Capture aborted for [{ lv_program }] (isolated session, rc={ lv_wrc }): { lv_msg }|
          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING capture_aborted.
    ENDCASE.
  ENDIF.

  lcl_b7_tcode_capture=>flatten_meta(
    EXPORTING ps_meta            = ls_meta
    IMPORTING ev_tier            = ev_tier
              ev_tier_label      = ev_tier_label
              ev_program         = ev_program
              ev_tcode           = ev_tcode
              ev_refused         = ev_refused
              ev_refusal_reason  = ev_refusal_reason
              ev_row_count       = ev_row_count
              ev_column_count    = ev_column_count
              ev_truncated       = ev_truncated
              ev_delimiter       = ev_delimiter
              ev_skipped_columns = ev_skipped_columns ).

ENDFUNCTION.
