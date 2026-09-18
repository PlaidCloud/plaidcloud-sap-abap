FUNCTION z_plaidcl_close.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TOKEN) TYPE  STRING
*"  EXPORTING
*"     VALUE(EV_STATUS) TYPE  STRING
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      CANCEL_FAILED
*"----------------------------------------------------------------------



  DATA ls_hdr           TYPE ty_plaidcl_stage_hdr.
  DATA ls_ctrl          TYPE ty_plaidcl_stage_ctrl.
  DATA lv_id            TYPE indx-srtfd.
  DATA lv_jobkey_id     TYPE indx-srtfd.
  DATA lv_ctrl_rc       TYPE i.
  DATA lv_cancel_rc     TYPE i.
  DATA lv_v1            TYPE symsgv.
  DATA lv_v2            TYPE symsgv.
  DATA lv_v3            TYPE symsgv.
  DATA lv_v4            TYPE symsgv.

  IF lcl_plaidcl_stage=>is_token( iv_token ) = abap_false.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |IV_TOKEN is not a staging token (PC_ + 19 hex): { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.

  lv_id = iv_token.
  IMPORT header = ls_hdr FROM DATABASE indx(zp) ID lv_id.
  IF sy-subrc = 0 AND ls_hdr-owner <> sy-uname.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Token not found: { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.
  IMPORT ctrl = ls_ctrl FROM DATABASE indx(za) ID lv_id.
  lv_ctrl_rc = sy-subrc.
  IF lv_ctrl_rc = 0 AND ls_ctrl-owner <> sy-uname.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Token not found: { iv_token }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
  ENDIF.

  " A job still running would otherwise keep a background work process
  " busy until it finishes, and the worker would then stage an orphan ZP
  " (up to 32 MB) nobody ever fetches. Reuse Z_PLAIDCL_B12_CANCEL's own
  " abort/delete logic (same function group, a local call) rather than
  " duplicating BP_JOB_ABORT here. NOT_FOUND (job record already gone) and
  " NOT_CANCELLABLE (already finished) are not errors: CLOSE proceeds to
  " release storage below either way. CANCEL_FAILED means the job is
  " still RUNNING and could not be stopped: releasing storage now would
  " orphan the ZP the worker is about to stage, so CLOSE stops here
  " instead, deleting nothing and reporting CANCEL_FAILED itself.
  IF lv_ctrl_rc = 0 AND ls_ctrl-jobcount IS NOT INITIAL.
    CALL FUNCTION 'Z_PLAIDCL_B12_CANCEL'
      EXPORTING iv_token = iv_token
      EXCEPTIONS
        invalid_input   = 1
        not_found       = 2
        not_cancellable = 3
        cancel_failed   = 4
        OTHERS          = 5.
    lv_cancel_rc = sy-subrc.
    IF lv_cancel_rc = 4.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Could not stop the still-running job for { iv_token }, not closed: | &&
                            |{ sy-msgv1 }{ sy-msgv2 }{ sy-msgv3 }{ sy-msgv4 }|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING cancel_failed.
    ENDIF.
  ENDIF.

  DELETE FROM DATABASE indx(zp) ID lv_id.
  DELETE FROM DATABASE indx(zq) ID lv_id.
  DELETE FROM DATABASE indx(za) ID lv_id.
  " SN1/SC1: a token closed before its background job ever ran (or started
  " but has not yet called the worker) leaves an orphaned job-key->token
  " mapping otherwise. Rebuild the same composite key RUN_ASYNC used, via
  " the shared LCL_PLAIDCL_B12_JOBKEY=>DERIVE.
  IF lv_ctrl_rc = 0 AND ls_ctrl-jobcount IS NOT INITIAL.
    lv_jobkey_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = ls_ctrl-jobname iv_jobcount = ls_ctrl-jobcount ).
    DELETE FROM DATABASE indx(zj) ID lv_jobkey_id.
  ENDIF.
  ev_status = `CLOSED`.
ENDFUNCTION.
