REPORT z_plaidcl_b12_worker.

INCLUDE z_plaidcl_stage_types.

START-OF-SELECTION.
  DATA gv_token    TYPE string.
  DATA gv_jobname  TYPE tbtco-jobname.
  DATA gv_jobcount TYPE tbtco-jobcount.
  DATA gs_jobkey   TYPE ty_plaidcl_job_key.
  DATA gv_id       TYPE indx-srtfd.
  " Only as the job step RUN_ASYNC schedules. From SA38 it would run a
  " capture in a dialog work process, outside RUN_ASYNC's checks.
  IF sy-batch <> abap_true.
    MESSAGE 'Z_PLAIDCL_B12_WORKER runs only as a background job step' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.

  " SN1: no PARAMETERS, so no token digit is ever readable in the job
  " step's variant (SM37/VARI/TBTCP). Discover our own job identity and
  " look up the token RUN_ASYNC staged under it (INDX ZJ); JOBCOUNT alone
  " can in theory recycle after a job is purged, so JOBNAME is compared
  " too before the mapping is trusted.
  CALL FUNCTION 'GET_JOB_RUNTIME_INFO'
    IMPORTING
      jobcount        = gv_jobcount
      jobname         = gv_jobname
    EXCEPTIONS
      no_runtime_info = 1
      OTHERS          = 2.
  IF sy-subrc <> 0.
    MESSAGE 'Z_PLAIDCL_B12_WORKER could not read its own job identity' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  " SC1: the same composite key RUN_ASYNC built, via the shared
  " LCL_PLAIDCL_B12_JOBKEY=>DERIVE -- never jobcount alone (it recycles
  " across job names) and never a raw SUBSTRING (a hand-scheduled job,
  " SM37, not RUN_ASYNC, can carry a name under 12 characters).
  gv_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = gv_jobname iv_jobcount = gv_jobcount ).
  IF gv_id IS INITIAL.
    MESSAGE 'Z_PLAIDCL_B12_WORKER found no job-key mapping for its own job' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  IMPORT jobkey = gs_jobkey FROM DATABASE indx(zj) ID gv_id.
  IF sy-subrc <> 0 OR gs_jobkey-jobname <> gv_jobname.
    MESSAGE 'Z_PLAIDCL_B12_WORKER found no job-key mapping for its own job' TYPE 'S' DISPLAY LIKE 'E'.
    RETURN.
  ENDIF.
  DELETE FROM DATABASE indx(zj) ID gv_id.

  gv_token = gs_jobkey-token.
  CALL FUNCTION 'Z_PLAIDCL_B12_EXECUTE'
    EXPORTING
      iv_token = gv_token.