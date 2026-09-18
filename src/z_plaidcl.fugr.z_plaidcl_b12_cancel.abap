FUNCTION z_plaidcl_b12_cancel.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TOKEN) TYPE  STRING
*"  EXPORTING
*"     VALUE(EV_JOB_STATUS) TYPE  STRING
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      NOT_CANCELLABLE
*"      CANCEL_FAILED
*"----------------------------------------------------------------------



* An ACTIVE job is aborted (BP_JOB_ABORT); a job that has not started is
* deleted (JOB_DELETE). Either way a FAILED result is staged, unless the
* job already staged one, so FETCH raises RUN_FAILED instead of NOT_READY.
* BP_JOB_ABORT can return before the step ends, so the step may still stage
* DONE over that FAILED; FETCH then sees TBTCO status A and still raises
* RUN_FAILED. EV_JOB_STATUS: CANCELLED | DELETED.
  DATA lv_sap       TYPE string.
  DATA ls_ctrl      TYPE ty_plaidcl_stage_ctrl.
  DATA ls_hdr       TYPE ty_plaidcl_stage_hdr.
  DATA lt_columns   TYPE dfies_table.
  DATA lt_rows      TYPE string_table.
  DATA lv_id        TYPE indx-srtfd.
  DATA lv_jobkey_id TYPE indx-srtfd.
  DATA lv_status    TYPE tbtco-status.
  DATA lv_rc        TYPE i.
  DATA lv_v1        TYPE symsgv.
  DATA lv_v2        TYPE symsgv.
  DATA lv_v3        TYPE symsgv.
  DATA lv_v4        TYPE symsgv.

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

  SELECT SINGLE status FROM tbtco INTO lv_status
    WHERE jobname = ls_ctrl-jobname AND jobcount = ls_ctrl-jobcount.
  IF sy-subrc <> 0.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Job { ls_ctrl-jobname } / { ls_ctrl-jobcount } no longer exists in TBTCO|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.

  CASE lv_status.
    WHEN 'F' OR 'A'.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Job { ls_ctrl-jobname } / { ls_ctrl-jobcount } already ended (TBTCO status { lv_status })|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_cancellable.

    WHEN 'R'.
      CALL FUNCTION 'BP_JOB_ABORT'
        EXPORTING
          jobcount                   = ls_ctrl-jobcount
          jobname                    = ls_ctrl-jobname
        EXCEPTIONS
          checking_of_job_has_failed = 1
          job_abort_has_failed       = 2
          job_does_not_exist         = 3
          job_is_not_active          = 4
          no_abort_privilege_given   = 5
          error_message              = 6
          OTHERS                     = 7.
      lv_rc = sy-subrc.
      IF lv_rc = 6.
        lv_sap = |: { lcl_plaidcl_stage=>message_text( ) }|.
      ENDIF.
      IF lv_rc <> 0.
        lcl_plaidcl_stage=>msg_chunks(
          EXPORTING iv_text = |BP_JOB_ABORT failed (subrc={ lv_rc }) for job { ls_ctrl-jobname } / { ls_ctrl-jobcount }{ lv_sap }|
          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING cancel_failed.
      ENDIF.
      ev_job_status = `CANCELLED`.

    WHEN OTHERS.
      CALL FUNCTION 'BP_JOB_DELETE'
        EXPORTING
          jobname       = ls_ctrl-jobname
          jobcount      = ls_ctrl-jobcount
        EXCEPTIONS
          error_message = 1
          OTHERS        = 2.
      lv_rc = sy-subrc.
      IF lv_rc = 1.
        lv_sap = |: { lcl_plaidcl_stage=>message_text( ) }|.
      ENDIF.
      IF lv_rc <> 0.
        lcl_plaidcl_stage=>msg_chunks(
          EXPORTING iv_text = |BP_JOB_DELETE failed (subrc={ lv_rc }) for job { ls_ctrl-jobname } / { ls_ctrl-jobcount }{ lv_sap }|
          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING cancel_failed.
      ENDIF.
      ev_job_status = `DELETED`.
  ENDCASE.

  DELETE FROM DATABASE indx(zq) ID lv_id.
  " The job never ran, or the worker never got past its own lookup: its
  " job-key->token mapping (SN1) would otherwise be orphaned forever.
  " SC1: rebuild the same composite key RUN_ASYNC used, via the shared
  " LCL_PLAIDCL_B12_JOBKEY=>DERIVE.
  lv_jobkey_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = ls_ctrl-jobname iv_jobcount = ls_ctrl-jobcount ).
  DELETE FROM DATABASE indx(zj) ID lv_jobkey_id.
  IMPORT header = ls_hdr FROM DATABASE indx(zp) ID lv_id.
  IF sy-subrc <> 0.
    ls_hdr-owner  = sy-uname.
    ls_hdr-status = `FAILED`.
    ls_hdr-reason = |Cancelled via Z_PLAIDCL_B12_CANCEL (job { ls_ctrl-jobname } / { ls_ctrl-jobcount })|.
    GET TIME STAMP FIELD ls_hdr-created_at.
    EXPORT header = ls_hdr columns = lt_columns rows = lt_rows TO DATABASE indx(zp) ID lv_id.
  ENDIF.
ENDFUNCTION.
