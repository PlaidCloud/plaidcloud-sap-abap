FUNCTION z_plaidcl_b12_run_async.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_REPORT) TYPE  PROGRAMM OPTIONAL
*"     VALUE(IV_MAX_ROWS) TYPE  I DEFAULT 10000
*"     VALUE(IT_SELECTION) TYPE  STRING_TABLE OPTIONAL
*"     VALUE(IV_JOBNAME) TYPE  STRING OPTIONAL
*"  EXPORTING
*"     VALUE(EV_TIER) TYPE  STRING
*"     VALUE(EV_TIER_LABEL) TYPE  STRING
*"     VALUE(EV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(EV_REFUSED) TYPE  BOOLE_D
*"     VALUE(EV_REFUSAL_REASON) TYPE  STRING
*"     VALUE(EV_TOKEN) TYPE  STRING
*"     VALUE(EV_JOBNAME) TYPE  STRING
*"     VALUE(EV_JOBCOUNT) TYPE  I
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      ROW_LIMIT_EXCEEDED
*"      NOT_FOUND
*"      NOT_AUTHORIZED
*"      TIER_A_UNSUPPORTED
*"      SUBMIT_FAILED
*"----------------------------------------------------------------------



  DATA lt_sel      TYPE ty_b7_seltab.
  DATA lv_sel_ok   TYPE abap_bool.
  DATA lv_sel_err  TYPE string.
  DATA lv_missing  TYPE string.
  DATA lv_program  TYPE programm.
  DATA lv_pgmna    TYPE tstc-pgmna.
  DATA lv_token    TYPE string.
  DATA lv_id       TYPE indx-srtfd.
  DATA lv_prefix   TYPE string.
  DATA lv_random   TYPE xstring.
  DATA lv_sap      TYPE string.
  DATA lv_jobname  TYPE tbtcjob-jobname.
  DATA lv_jobcount TYPE tbtcjob-jobcount.
  DATA lv_rc       TYPE i.
  DATA lv_text     TYPE string.
  DATA ls_ctrl     TYPE ty_plaidcl_stage_ctrl.
  DATA ls_input    TYPE ty_plaidcl_job_input.
  DATA ls_jobkey   TYPE ty_plaidcl_job_key.
  DATA lv_jobkey_id TYPE indx-srtfd.
  DATA lv_v1       TYPE symsgv.
  DATA lv_v2       TYPE symsgv.
  DATA lv_v3       TYPE symsgv.
  DATA lv_v4       TYPE symsgv.

  IF ( iv_tcode IS INITIAL AND iv_report IS INITIAL )
     OR ( iv_tcode IS NOT INITIAL AND iv_report IS NOT INITIAL ).
    MESSAGE e001(00) WITH 'Supply exactly one of IV_TCODE and IV_REPORT' RAISING invalid_input.
  ENDIF.
  IF iv_max_rows <= 0.
    MESSAGE e001(00) WITH 'IV_MAX_ROWS must be positive' RAISING invalid_input.
  ENDIF.
  IF iv_max_rows > gc_plaidcl_max_rows.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_MAX_ROWS { iv_max_rows } exceeds the cap of { gc_plaidcl_max_rows }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING row_limit_exceeded.
  ENDIF.

  lcl_b7_tcode_capture=>decode_selection(
    EXPORTING pt_wire  = it_selection
    IMPORTING et_sel   = lt_sel
              ev_ok    = lv_sel_ok
              ev_error = lv_sel_err ).
  IF lv_sel_ok = abap_false.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = lv_sel_err
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  IF iv_report IS NOT INITIAL.
    lv_program = iv_report.
  ELSE.
    SELECT SINGLE pgmna FROM tstc INTO lv_pgmna WHERE tcode = iv_tcode.
    IF sy-subrc <> 0.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Transaction { iv_tcode } does not exist|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
    ENDIF.
    IF lv_pgmna IS INITIAL.
      ev_refused        = abap_true.
      ev_refusal_reason = |Refused: transaction [{ iv_tcode }] has no TSTC-PGMNA (parameter, OO or Web Dynpro transaction).|.
      RETURN.
    ENDIF.
    lv_program = lv_pgmna.
  ENDIF.

  " Contract 1 -- before read_source reads the program source.
  IF iv_tcode IS INITIAL.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
      EXPORTING
        iv_program        = lv_program
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
  ELSE.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
      EXPORTING
        iv_program        = lv_program
        iv_tcode          = iv_tcode
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
  ENDIF.
  lv_rc = sy-subrc.
  IF lv_rc = 2.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Program { lv_program } does not exist|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ELSEIF lv_rc <> 0.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Not authorized to run { lv_program } (Z_PLAIDCL_B10_CHECK_PROGRAM subrc={ lv_rc })|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
  ENDIF.

  " One synchronous source expansion serves the tier and the selection check.
  DATA(ls_source) = lcl_b7_tcode_capture=>read_source( lv_program ).
  IF ls_source-denied = abap_true.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = ls_source-denied_reason
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
  ENDIF.
  DATA(ls_meta) = lcl_b7_tcode_capture=>classify_source( ls_source ).
  IF ls_meta-refused = abap_true.
    ev_tier           = ls_meta-tier.
    ev_tier_label     = ls_meta-tier_label.
    ev_program        = lv_program.
    ev_refused        = abap_true.
    ev_refusal_reason = ls_meta-refusal_reason.
    RETURN.
  ENDIF.
  IF ls_meta-tier = 'A'.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |{ lv_program } is Tier A (SALV): its capture is cancelled in a background job | &&
                          |(TBTCO status A). Use Z_PLAIDCL_B7_RUN_TCODE.|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING tier_a_unsupported.
  ENDIF.

  lcl_b7_tcode_capture=>check_coverage(
    EXPORTING ps_source         = ls_source
              pt_selection      = lt_sel
    IMPORTING ev_ok             = lv_sel_ok
              ev_missing_fields = lv_missing ).
  IF lv_sel_ok = abap_false.
    ev_tier           = ls_meta-tier.
    ev_tier_label     = ls_meta-tier_label.
    ev_program        = lv_program.
    ev_refused        = abap_true.
    ev_refusal_reason = |Refused: obligatory selection field(s) not covered by IT_SELECTION: [{ lv_missing }].|.
    RETURN.
  ENDIF.

  lv_token = lcl_plaidcl_stage=>new_token( ).
  IF lv_token IS INITIAL.
    MESSAGE e001(00) WITH 'GENERATE_SEC_RANDOM returned no random bytes' RAISING submit_failed.
  ENDIF.
  lv_id = lv_token.

  IF iv_jobname IS INITIAL.
    lv_prefix = `PLAIDCLB12`.
  ELSE.
    lv_prefix = to_upper( iv_jobname ).
    IF strlen( lv_prefix ) > 12.
      lv_prefix = substring( val = lv_prefix len = 12 ).
    ENDIF.
  ENDIF.
  " SM37 shows job names to anyone with job display rights: use separate
  " random bytes, never token digits.
  CALL FUNCTION 'GENERATE_SEC_RANDOM'
    EXPORTING
      length         = 6
    IMPORTING
      random         = lv_random
    EXCEPTIONS
      invalid_length = 1
      no_memory      = 2
      internal_error = 3
      error_message  = 4
      OTHERS         = 5.
  IF sy-subrc <> 0 OR xstrlen( lv_random ) < 6.
    MESSAGE e001(00) WITH 'GENERATE_SEC_RANDOM returned no random bytes' RAISING submit_failed.
  ENDIF.
  lv_jobname = |{ lv_prefix }_{ lv_random }|.

  CALL FUNCTION 'JOB_OPEN'
    EXPORTING
      jobname          = lv_jobname
    IMPORTING
      jobcount         = lv_jobcount
    EXCEPTIONS
      cant_create_job  = 1
      invalid_job_data = 2
      jobname_missing  = 3
      error_message    = 4
      OTHERS           = 5.
  lv_rc = sy-subrc.
  IF lv_rc = 4.
    lv_sap = |: { lcl_plaidcl_stage=>message_text( ) }|.
  ENDIF.
  IF lv_rc <> 0.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |JOB_OPEN failed (subrc={ lv_rc }) for job { lv_jobname }{ lv_sap }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING submit_failed.
  ENDIF.

  " ctrl before job input: B9 reaps job input that has no ctrl record.
  ls_ctrl-owner    = sy-uname.
  ls_ctrl-jobname  = lv_jobname.
  ls_ctrl-jobcount = lv_jobcount.
  GET TIME STAMP FIELD ls_ctrl-accessed.
  " STATUS measures elapsed from here, on TBTCO's clock.
  GET TIME.
  ls_ctrl-submit_date = sy-datum.
  ls_ctrl-submit_time = sy-uzeit.
  EXPORT ctrl = ls_ctrl TO DATABASE indx(za) ID lv_id.
  ls_input-program  = lv_program.
  ls_input-tcode    = iv_tcode.
  ls_input-max_rows = iv_max_rows.
  EXPORT input = ls_input selection = it_selection TO DATABASE indx(zq) ID lv_id.

  " The worker takes no PARAMETERS (SN1): it discovers its own job identity
  " via GET_JOB_RUNTIME_INFO and looks up its token here, so no token digit
  " is ever readable in the job step's variant (SM37/VARI/TBTCP).
  " SC1: JOBCOUNT alone (HHMMSS+2 digits) is unique only per JOBNAME, so two
  " RUN_ASYNC calls in the same second would collide on it under different
  " job names. LCL_PLAIDCL_B12_JOBKEY=>DERIVE keys on the job name's 12-hex
  " random suffix (always its last 12 characters -- see LV_JOBNAME above)
  " plus JOBCOUNT: 20 characters, within INDX-SRTFD's 22.
  lv_jobkey_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = lv_jobname iv_jobcount = lv_jobcount ).
  ls_jobkey-jobname  = lv_jobname.
  ls_jobkey-jobcount = lv_jobcount.
  ls_jobkey-token    = lv_token.
  EXPORT jobkey = ls_jobkey TO DATABASE indx(zj) ID lv_jobkey_id.

  SUBMIT z_plaidcl_b12_worker
    VIA JOB lv_jobname NUMBER lv_jobcount
    AND RETURN.
  lv_rc = sy-subrc.
  IF lv_rc <> 0.
    lv_text = |SUBMIT VIA JOB failed (subrc={ lv_rc }) for { lv_program }, job { lv_jobname }|.
  ELSE.
    CALL FUNCTION 'JOB_CLOSE'
      EXPORTING
        jobcount             = lv_jobcount
        jobname              = lv_jobname
        strtimmed            = abap_true
      EXCEPTIONS
        cant_start_immediate = 1
        invalid_startdate    = 2
        jobname_missing      = 3
        job_close_failed     = 4
        job_nosteps          = 5
        job_notex            = 6
        lock_failed          = 7
        error_message        = 8
        OTHERS               = 9.
    lv_rc = sy-subrc.
    IF lv_rc = 8.
      lv_sap = |: { lcl_plaidcl_stage=>message_text( ) }|.
    ENDIF.
    IF lv_rc <> 0.
      lv_text = |JOB_CLOSE failed (subrc={ lv_rc }) for job { lv_jobname } / { lv_jobcount }{ lv_sap }|.
    ENDIF.
  ENDIF.

  IF lv_text IS NOT INITIAL.
    CLEAR lv_sap.
    CALL FUNCTION 'BP_JOB_DELETE'
      EXPORTING
        jobname       = lv_jobname
        jobcount      = lv_jobcount
      EXCEPTIONS
        error_message = 1
        OTHERS        = 2.
    lv_rc = sy-subrc.
    IF lv_rc = 1.
      lv_sap = |: { lcl_plaidcl_stage=>message_text( ) }|.
    ENDIF.
    IF lv_rc <> 0.
      lv_text = |{ lv_text }; BP_JOB_DELETE also failed (subrc={ lv_rc }{ lv_sap }), remove the job in SM37|.
    ENDIF.
    DELETE FROM DATABASE indx(zq) ID lv_id.
    DELETE FROM DATABASE indx(za) ID lv_id.
    DELETE FROM DATABASE indx(zj) ID lv_jobkey_id.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = lv_text
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING submit_failed.
  ENDIF.

  ev_tier       = ls_meta-tier.
  ev_tier_label = ls_meta-tier_label.
  ev_program    = lv_program.
  ev_refused    = abap_false.
  ev_token      = lv_token.
  ev_jobname    = lv_jobname.
  ev_jobcount   = lv_jobcount.
ENDFUNCTION.
