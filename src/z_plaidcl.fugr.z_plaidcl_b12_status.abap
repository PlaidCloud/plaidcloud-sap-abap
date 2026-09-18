FUNCTION z_plaidcl_b12_status.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TOKEN) TYPE  STRING
*"  EXPORTING
*"     VALUE(EV_JOB_STATUS) TYPE  STRING
*"     VALUE(EV_ELAPSED_SECS) TYPE  I
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"----------------------------------------------------------------------



* EV_JOB_STATUS: SCHEDULED | RELEASED | READY | SUSPENDED | ACTIVE |
* FINISHED | CANCELLED. EV_ELAPSED_SECS runs from submission (RUN_ASYNC)
* to the job's end, or to now while it has not ended. It includes time the
* job waits (P/S/Y/Z) for a free background work process, so a platform
* timeout fires even for a job that never starts. Every call stamps
* ZA-accessed, so polling STATUS keeps the token alive against B9.
  DATA ls_ctrl TYPE ty_plaidcl_stage_ctrl.
  DATA lv_id   TYPE indx-srtfd.
  DATA lv_date TYPE d.
  DATA lv_time TYPE t.
  DATA lv_v1   TYPE symsgv.
  DATA lv_v2   TYPE symsgv.
  DATA lv_v3   TYPE symsgv.
  DATA lv_v4   TYPE symsgv.

  IF lcl_plaidcl_stage=>is_token( iv_token ) = abap_false.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_TOKEN is not a staging token (PC_ + 19 hex): { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  lv_id = iv_token.
  IMPORT ctrl = ls_ctrl FROM DATABASE indx(za) ID lv_id.
  IF sy-subrc <> 0 OR ls_ctrl-owner <> sy-uname OR ls_ctrl-jobcount IS INITIAL.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |No background job for token { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.

  SELECT SINGLE status, enddate, endtime
    FROM tbtco
    WHERE jobname = @ls_ctrl-jobname AND jobcount = @ls_ctrl-jobcount
    INTO @DATA(ls_job).
  IF sy-subrc <> 0.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Job { ls_ctrl-jobname } / { ls_ctrl-jobcount } no longer exists in TBTCO|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.

  ev_job_status = SWITCH string( ls_job-status
                    WHEN 'P' THEN `SCHEDULED`
                    WHEN 'S' THEN `RELEASED`
                    WHEN 'Y' THEN `READY`
                    WHEN 'Z' THEN `SUSPENDED`
                    WHEN 'R' THEN `ACTIVE`
                    WHEN 'F' THEN `FINISHED`
                    WHEN 'A' THEN `CANCELLED`
                    ELSE |UNKNOWN_{ ls_job-status }| ).

  " Submission date/time are sy-datum/sy-uzeit, TBTCO's clock. RUN_ASYNC
  " always sets them (an initial date here overflowed the integer on A4H).
  " TBTCO leaves an unset end date blank, not 00000000, so IS INITIAL misses it.
  IF ls_job-enddate CO ' 0'.
    GET TIME.
    lv_date = sy-datum.
    lv_time = sy-uzeit.
  ELSE.
    lv_date = ls_job-enddate.
    lv_time = ls_job-endtime.
  ENDIF.
  ev_elapsed_secs = ( lv_date - ls_ctrl-submit_date ) * 86400 + ( lv_time - ls_ctrl-submit_time ).

  IF lcl_plaidcl_stage=>touch( iv_token ) = abap_false.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Token { iv_token } was closed or reaped during the call|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.
ENDFUNCTION.
