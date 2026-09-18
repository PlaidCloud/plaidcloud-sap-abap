FUNCTION z_plaidcl_fetch.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TOKEN) TYPE  STRING
*"     VALUE(IV_OFFSET) TYPE  I
*"     VALUE(IV_PAGE_SIZE) TYPE  I DEFAULT 5000
*"  EXPORTING
*"     VALUE(ET_COLUMNS) TYPE  DFIES_TABLE
*"     VALUE(ET_ROWS) TYPE  STRING_TABLE
*"     VALUE(EV_FROM_POS) TYPE  I
*"     VALUE(EV_ROW_COUNT) TYPE  I
*"     VALUE(EV_TOTAL_ROWS) TYPE  I
*"     VALUE(EV_HAS_MORE) TYPE  BOOLE_D
*"     VALUE(EV_TRUNCATED) TYPE  BOOLE_D
*"     VALUE(EV_STATUS) TYPE  STRING
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      ROW_LIMIT_EXCEEDED
*"      NOT_FOUND
*"      NOT_READY
*"      RUN_FAILED
*"----------------------------------------------------------------------



  DATA ls_hdr        TYPE ty_plaidcl_stage_hdr.
  DATA ls_ctrl       TYPE ty_plaidcl_stage_ctrl.
  DATA lt_rows       TYPE string_table.
  DATA lv_id         TYPE indx-srtfd.
  DATA lv_ctrl_found TYPE abap_bool.
  DATA lv_job_found  TYPE abap_bool.
  DATA lv_job_status TYPE tbtco-status.
  DATA lv_from       TYPE i.
  DATA lv_to         TYPE i.
  DATA lv_v1         TYPE symsgv.
  DATA lv_v2         TYPE symsgv.
  DATA lv_v3         TYPE symsgv.
  DATA lv_v4         TYPE symsgv.

  IF lcl_plaidcl_stage=>is_token( iv_token ) = abap_false.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_TOKEN is not a staging token (PC_ + 19 hex): { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.
  IF iv_page_size <= 0 OR iv_offset < 0.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_PAGE_SIZE must be > 0 and IV_OFFSET >= 0, got { iv_page_size } / { iv_offset }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.
  IF iv_page_size > gc_plaidcl_max_rows.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_PAGE_SIZE { iv_page_size } exceeds the cap of { gc_plaidcl_max_rows }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING row_limit_exceeded.
  ENDIF.

  lv_id = iv_token.

  " Job state is read BEFORE the result: a job seen as ended here had
  " already committed whatever it was going to stage.
  IMPORT ctrl = ls_ctrl FROM DATABASE indx(za) ID lv_id.
  lv_ctrl_found = xsdbool( sy-subrc = 0 ).
  IF lv_ctrl_found = abap_true AND ls_ctrl-jobcount IS NOT INITIAL.
    SELECT SINGLE status FROM tbtco INTO lv_job_status
      WHERE jobname = ls_ctrl-jobname AND jobcount = ls_ctrl-jobcount.
    lv_job_found = xsdbool( sy-subrc = 0 ).
  ENDIF.

  IMPORT header = ls_hdr columns = et_columns rows = lt_rows FROM DATABASE indx(zp) ID lv_id.
  IF sy-subrc <> 0.
    " A ctrl record with no job never gets a result staged under it.
    IF lv_ctrl_found = abap_false OR ls_ctrl-owner <> sy-uname OR ls_ctrl-jobcount IS INITIAL.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Token not found, already closed or reaped: { iv_token }|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
    ENDIF.
    IF lv_job_found = abap_false OR lv_job_status = 'A' OR lv_job_status = 'F'.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Background job { ls_ctrl-jobname } / { ls_ctrl-jobcount } ended | &&
                            |(TBTCO status [{ lv_job_status }]) without staging a result|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING run_failed.
    ENDIF.
    IF lcl_plaidcl_stage=>touch( iv_token ) = abap_false.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Token not found, already closed or reaped: { iv_token }|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
    ENDIF.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Result for { iv_token } is not staged yet; poll Z_PLAIDCL_B12_STATUS|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_ready.
  ENDIF.

  IF ls_hdr-owner <> sy-uname.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Token not found, already closed or reaped: { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.
  IF ls_hdr-status <> `DONE`.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = ls_hdr-reason
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING run_failed.
  ENDIF.
  " CANCEL race: BP_JOB_ABORT can return before the job step ends, so the
  " step's DONE export can overwrite the FAILED result CANCEL staged. Read
  " TBTCO again, after the result: a cancelled job never serves data.
  IF ls_ctrl-jobcount IS NOT INITIAL.
    SELECT SINGLE status FROM tbtco INTO lv_job_status
      WHERE jobname = ls_ctrl-jobname AND jobcount = ls_ctrl-jobcount.
    IF sy-subrc = 0 AND lv_job_status = 'A'.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Background job { ls_ctrl-jobname } / { ls_ctrl-jobcount } was cancelled | &&
                            |(TBTCO status A); its staged result is not served|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING run_failed.
    ENDIF.
  ENDIF.

  ev_total_rows = lines( lt_rows ).
  IF iv_offset > ev_total_rows.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_OFFSET { iv_offset } is past the end ({ ev_total_rows } rows)|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  lv_to = iv_offset + iv_page_size.
  IF lv_to > ev_total_rows.
    lv_to = ev_total_rows.
  ENDIF.
  IF lv_to > iv_offset.
    lv_from = iv_offset + 1.
    APPEND LINES OF lt_rows FROM lv_from TO lv_to TO et_rows.
  ENDIF.

  ev_from_pos   = iv_offset.
  ev_row_count  = lines( et_rows ).
  ev_has_more   = xsdbool( lv_to < ev_total_rows ).
  ev_truncated  = ls_hdr-truncated.
  ev_status     = COND string( WHEN ev_has_more = abap_true THEN `OK` ELSE `DONE` ).

  IF lcl_plaidcl_stage=>touch( iv_token ) = abap_false.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Token not found, already closed or reaped: { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.
ENDFUNCTION.
