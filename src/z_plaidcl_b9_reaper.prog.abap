REPORT z_plaidcl_b9_reaper.

INCLUDE z_plaidcl_stage_types.

CONSTANTS gc_b9_reap_ttl_secs TYPE i VALUE 86400.
" LCL_PLAIDCL_STAGE=>IS_TOKEN's shape; matches() ignores CHAR trailing blanks.
CONSTANTS gc_b9_token_regex TYPE c LENGTH 15 VALUE 'PC_[0-9A-F]{19}'.

TYPES: BEGIN OF ty_b9_stat,
         srtfd          TYPE indx-srtfd,
         last_activity  TYPE timestampl,
         age_secs       TYPE i,
         total_rows     TYPE i,
         bytes          TYPE i,
         ttl_exceeded   TYPE abap_bool,
         reaped         TYPE abap_bool,
         skipped_active TYPE abap_bool,
         stale_layout   TYPE abap_bool,
       END OF ty_b9_stat.
TYPES tt_b9_stat  TYPE STANDARD TABLE OF ty_b9_stat WITH EMPTY KEY.
TYPES tt_b9_srtfd TYPE STANDARD TABLE OF indx-srtfd WITH EMPTY KEY.

TYPES: BEGIN OF ty_b9v_job,
         jobname  TYPE tbtcjob-jobname,
         jobcount TYPE tbtcjob-jobcount,
       END OF ty_b9v_job.
TYPES tt_b9v_jobs TYPE STANDARD TABLE OF ty_b9v_job WITH EMPTY KEY.

SELECTION-SCREEN COMMENT /1(60) txt_dry.
PARAMETERS p_dryrun AS CHECKBOX DEFAULT abap_true.

INITIALIZATION.
  " SELECTION-SCREEN COMMENT names are capped at 8 characters.
  txt_dry = 'Dry run: report only, never delete (uncheck to actually reap)'.

START-OF-SELECTION.
  PERFORM run_reaper USING p_dryrun.

FORM now_timestamp CHANGING pv_now TYPE timestampl.
  GET TIME STAMP FIELD pv_now.
ENDFORM.

FORM far_past_timestamp CHANGING pv_tstmp TYPE timestampl.
  DATA lv_date TYPE d VALUE '20200101'.
  DATA lv_time TYPE t VALUE '000000'.
  CONVERT DATE lv_date TIME lv_time INTO TIME STAMP pv_tstmp TIME ZONE 'UTC'.
ENDFORM.

" TIMESTAMPL is not linear in seconds across a day/month boundary, so
" never subtract two of them with plain arithmetic.
FORM age_seconds USING pv_from TYPE timestampl
                       pv_now  TYPE timestampl
              CHANGING pv_secs TYPE i.
  " P LENGTH 8 DECIMALS 7 overflows past ~3 years of idle time (dumped
  " BCD_FIELD_OVERFLOW on A4H for a token idle since 2020).
  DATA lv_secs TYPE p LENGTH 16 DECIMALS 7.
  lv_secs = cl_abap_tstmp=>subtract( tstmp1 = pv_now tstmp2 = pv_from ).
  pv_secs = lv_secs.
ENDFORM.

FORM mark_eligible USING pv_age_secs  TYPE i
                CHANGING pv_eligible TYPE abap_bool.
  pv_eligible = boolc( pv_age_secs > gc_b9_reap_ttl_secs ).
ENDFORM.

FORM collect_tokens CHANGING pt_srtfd TYPE tt_b9_srtfd.
  DATA lv_srtfd TYPE indx-srtfd.
  " PC_ then exactly 19 single-character wildcards: SQL cannot say "hex".
  SELECT DISTINCT srtfd FROM indx INTO TABLE pt_srtfd
    WHERE relid IN ('ZP', 'ZQ', 'ZA')
      AND srtfd LIKE 'PC#____________________' ESCAPE '#'.
  LOOP AT pt_srtfd INTO lv_srtfd.
    IF NOT matches( val = lv_srtfd regex = gc_b9_token_regex ).
      DELETE pt_srtfd.
    ENDIF.
  ENDLOOP.
ENDFORM.

" A record staged under an OLDER layout of TY_PLAIDCL_STAGE_HDR/_CTRL (an
" upgrade from before a type change) dumps CX_SY_IMPORT_MISMATCH_ERROR on
" a plain IMPORT: caught here and reported via PV_STALE, never fatal. A
" record no current FM can decode is stale by definition, so the caller
" reaps it outright rather than trying to age it.
FORM last_activity USING pv_srtfd TYPE indx-srtfd
                CHANGING pv_last  TYPE timestampl
                         pv_stale TYPE abap_bool.
  DATA ls_hdr  TYPE ty_plaidcl_stage_hdr.
  DATA ls_ctrl TYPE ty_plaidcl_stage_ctrl.
  CLEAR: pv_last, pv_stale.
  TRY.
      IMPORT header = ls_hdr FROM DATABASE indx(zp) ID pv_srtfd.
    CATCH cx_sy_import_mismatch_error.
      pv_stale = abap_true.
      RETURN.
  ENDTRY.
  TRY.
      IMPORT ctrl = ls_ctrl FROM DATABASE indx(za) ID pv_srtfd.
    CATCH cx_sy_import_mismatch_error.
      pv_stale = abap_true.
      RETURN.
  ENDTRY.
  pv_last = ls_hdr-created_at.
  IF ls_ctrl-accessed > pv_last.
    pv_last = ls_ctrl-accessed.
  ENDIF.
ENDFORM.

FORM stat_for_token USING pv_srtfd TYPE indx-srtfd
                          pv_now   TYPE timestampl
                 CHANGING ps_stat  TYPE ty_b9_stat
                          pv_found TYPE abap_bool.
  DATA lt_rows  TYPE string_table.
  DATA lv_row   TYPE string.
  DATA lv_hits  TYPE i.
  DATA lv_stale TYPE abap_bool.

  CLEAR ps_stat.
  pv_found = abap_false.
  IF NOT matches( val = pv_srtfd regex = gc_b9_token_regex ).
    RETURN.
  ENDIF.

  SELECT COUNT( * ) FROM indx INTO lv_hits
    WHERE relid IN ('ZP', 'ZQ', 'ZA') AND srtfd = pv_srtfd.
  IF lv_hits = 0.
    RETURN.
  ENDIF.
  pv_found = abap_true.
  ps_stat-srtfd = pv_srtfd.

  " An upgrade from an older TY_PLAIDCL_STAGE_HDR/ROWS layout dumps a
  " plain IMPORT: caught, and the record is stale by definition (no
  " current FM can ever decode it), so the caller reaps it on sight.
  TRY.
      IMPORT rows = lt_rows FROM DATABASE indx(zp) ID pv_srtfd.
    CATCH cx_sy_import_mismatch_error.
      ps_stat-stale_layout = abap_true.
      ps_stat-ttl_exceeded = abap_true.
      RETURN.
  ENDTRY.
  LOOP AT lt_rows INTO lv_row.
    ps_stat-bytes = ps_stat-bytes + strlen( lv_row ).
  ENDLOOP.
  ps_stat-total_rows = lines( lt_rows ).

  PERFORM last_activity USING pv_srtfd CHANGING ps_stat-last_activity lv_stale.
  IF lv_stale = abap_true.
    ps_stat-stale_layout = abap_true.
    ps_stat-ttl_exceeded = abap_true.
    RETURN.
  ENDIF.
  IF ps_stat-last_activity IS INITIAL.
    ps_stat-ttl_exceeded = abap_true.
    RETURN.
  ENDIF.
  PERFORM age_seconds USING ps_stat-last_activity pv_now CHANGING ps_stat-age_secs.
  PERFORM mark_eligible USING ps_stat-age_secs CHANGING ps_stat-ttl_exceeded.
ENDFORM.

FORM reap_token USING pv_srtfd  TYPE indx-srtfd
                      pv_seen   TYPE timestampl
             CHANGING pv_reaped TYPE abap_bool.
  DATA lv_last  TYPE timestampl.
  DATA lv_stale TYPE abap_bool.

  pv_reaped = abap_false.
  PERFORM last_activity USING pv_srtfd CHANGING lv_last lv_stale.
  " Stale-layout tokens are reaped directly by SWEEP_GIVEN_TOKENS (no
  " concurrent-fetch race to protect against for a record no current FM
  " can decode); if one turns up stale only now, back off and let the
  " next run's STAT_FOR_TOKEN catch and reap it via that path instead.
  IF lv_stale = abap_true OR lv_last <> pv_seen.
    RETURN.
  ENDIF.

  DELETE FROM DATABASE indx(zp) ID pv_srtfd.
  DELETE FROM DATABASE indx(zq) ID pv_srtfd.
  DELETE FROM DATABASE indx(za) ID pv_srtfd.
  pv_reaped = abap_true.
ENDFORM.

FORM aggregate_budget USING pt_stats         TYPE tt_b9_stat
                   CHANGING pv_total_tokens TYPE i
                            pv_total_bytes  TYPE i
                            pv_oldest_secs  TYPE i.
  DATA ls_stat TYPE ty_b9_stat.

  pv_total_tokens = lines( pt_stats ).
  pv_total_bytes  = 0.
  pv_oldest_secs  = 0.
  LOOP AT pt_stats INTO ls_stat.
    pv_total_bytes = pv_total_bytes + ls_stat-bytes.
    IF ls_stat-age_secs > pv_oldest_secs.
      pv_oldest_secs = ls_stat-age_secs.
    ENDIF.
  ENDLOOP.
ENDFORM.

FORM write_report USING pt_stats        TYPE tt_b9_stat
                        pv_dryrun      TYPE abap_bool
                        pv_reap_cnt    TYPE i
                        pv_jobkey_cnt  TYPE i.
  DATA lv_total_tokens TYPE i.
  DATA lv_total_bytes  TYPE i.
  DATA lv_oldest_secs  TYPE i.
  DATA ls_stat         TYPE ty_b9_stat.
  DATA lv_mode         TYPE string.

  PERFORM aggregate_budget USING pt_stats CHANGING lv_total_tokens lv_total_bytes lv_oldest_secs.
  IF pv_dryrun = abap_true.
    lv_mode = 'DRY-RUN (report only, nothing deleted)'.
  ELSE.
    lv_mode = 'LIVE (idle tokens deleted)'.
  ENDIF.

  WRITE: / 'B9 STAGING REAPER -- DISK BUDGET'.
  WRITE: / 'mode:', lv_mode.
  WRITE: / 'idle ttl (seconds):', gc_b9_reap_ttl_secs.
  WRITE: / 'tokens:', lv_total_tokens.
  WRITE: / 'staged row characters:', lv_total_bytes.
  WRITE: / 'longest idle (seconds):', lv_oldest_secs.
  WRITE: / 'reaped this run:', pv_reap_cnt.
  WRITE: / 'job-key mappings (ZJ) reaped this run:', pv_jobkey_cnt.
  ULINE.
  WRITE: / 'token / idle_secs / rows / chars / ttl_exceeded / reaped / skipped_active / stale_layout'.
  LOOP AT pt_stats INTO ls_stat.
    WRITE: / ls_stat-srtfd, ls_stat-age_secs, ls_stat-total_rows, ls_stat-bytes,
             ls_stat-ttl_exceeded, ls_stat-reaped, ls_stat-skipped_active, ls_stat-stale_layout.
  ENDLOOP.
ENDFORM.

" B12's job-key->token mapping (SN1) is consumed and deleted by the worker,
" RUN_ASYNC's own submit-failure cleanup, and Z_PLAIDCL_CLOSE. A mapping
" still on file for a job that has already ended (or whose TBTCO row is
" gone) can only be an orphan -- no job step will ever run to claim it -- so
" unlike a PC_ token there is no idle grace period.
FORM collect_job_keys CHANGING pt_srtfd TYPE tt_b9_srtfd.
  SELECT DISTINCT srtfd FROM indx INTO TABLE pt_srtfd WHERE relid = 'ZJ'.
ENDFORM.

FORM sweep_given_job_keys USING pt_srtfd    TYPE tt_b9_srtfd
                                pv_dryrun   TYPE abap_bool
                       CHANGING pv_reap_cnt TYPE i.
  DATA lv_id          TYPE indx-srtfd.
  DATA ls_jobkey      TYPE ty_plaidcl_job_key.
  DATA lv_status      TYPE tbtco-status.
  DATA lv_ended       TYPE abap_bool.
  DATA lv_import_rc   TYPE i.
  DATA lv_recomputed  TYPE indx-srtfd.

  pv_reap_cnt = 0.
  LOOP AT pt_srtfd INTO lv_id.
    CLEAR ls_jobkey.
    TRY.
        IMPORT jobkey = ls_jobkey FROM DATABASE indx(zj) ID lv_id.
        lv_import_rc = sy-subrc.
      CATCH cx_sy_import_mismatch_error.
        CONTINUE.
    ENDTRY.
    IF lv_import_rc <> 0.
      CONTINUE.
    ENDIF.
    " SC1: recompute the key from the payload's own jobname+jobcount via
    " the shared LCL_PLAIDCL_B12_JOBKEY=>DERIVE, and only act on a row
    " that produces exactly this id. A foreign or stale-layout INDX(ZJ)
    " record (or one whose mismatched IMPORT was just caught above) is
    " left alone -- this is a stronger check than a shape regex, and
    " needs no separate JOBCOUNT-from-id substring.
    lv_recomputed = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = ls_jobkey-jobname iv_jobcount = ls_jobkey-jobcount ).
    IF lv_recomputed <> lv_id.
      CONTINUE.
    ENDIF.
    CLEAR lv_status.
    SELECT SINGLE status FROM tbtco INTO lv_status
      WHERE jobname = ls_jobkey-jobname AND jobcount = ls_jobkey-jobcount.
    lv_ended = xsdbool( sy-subrc <> 0 OR lv_status = 'F' OR lv_status = 'A' ).
    IF lv_ended = abap_true AND pv_dryrun = abap_false.
      DELETE FROM DATABASE indx(zj) ID lv_id.
      pv_reap_cnt = pv_reap_cnt + 1.
    ENDIF.
  ENDLOOP.
ENDFORM.

" Takes an explicit id list so the DANGEROUS tests sweep only what they staged.
FORM sweep_given_tokens USING pt_srtfd     TYPE tt_b9_srtfd
                              pv_dryrun    TYPE abap_bool
                     CHANGING pt_stats     TYPE tt_b9_stat
                              pv_reap_cnt  TYPE i.
  DATA lv_now    TYPE timestampl.
  DATA lv_srtfd  TYPE indx-srtfd.
  DATA ls_stat   TYPE ty_b9_stat.
  DATA lv_found  TYPE abap_bool.
  DATA lv_reaped TYPE abap_bool.

  CLEAR pt_stats.
  pv_reap_cnt = 0.
  PERFORM now_timestamp CHANGING lv_now.

  LOOP AT pt_srtfd INTO lv_srtfd.
    PERFORM stat_for_token USING lv_srtfd lv_now CHANGING ls_stat lv_found.
    IF lv_found = abap_false.
      CONTINUE.
    ENDIF.
    IF ls_stat-stale_layout = abap_true.
      " Stale by definition (no current FM can decode it): no idle grace
      " period, and no concurrent-fetch race to protect against the way
      " REAP_TOKEN does for an idle-but-servable record, so delete it
      " directly here rather than through REAP_TOKEN's re-check.
      IF pv_dryrun = abap_false.
        DELETE FROM DATABASE indx(zp) ID lv_srtfd.
        DELETE FROM DATABASE indx(zq) ID lv_srtfd.
        DELETE FROM DATABASE indx(za) ID lv_srtfd.
        ls_stat-reaped = abap_true.
        pv_reap_cnt = pv_reap_cnt + 1.
      ENDIF.
      APPEND ls_stat TO pt_stats.
      CONTINUE.
    ENDIF.
    IF ls_stat-ttl_exceeded = abap_true AND pv_dryrun = abap_false.
      PERFORM reap_token USING lv_srtfd ls_stat-last_activity CHANGING lv_reaped.
      IF lv_reaped = abap_true.
        ls_stat-reaped = abap_true.
        pv_reap_cnt = pv_reap_cnt + 1.
      ELSE.
        ls_stat-skipped_active = abap_true.
      ENDIF.
    ENDIF.
    APPEND ls_stat TO pt_stats.
  ENDLOOP.
ENDFORM.

FORM run_reaper USING pv_dryrun TYPE abap_bool.
  DATA lt_srtfd       TYPE tt_b9_srtfd.
  DATA lt_stats       TYPE tt_b9_stat.
  DATA lv_reap_cnt    TYPE i.
  DATA lt_jobkeys     TYPE tt_b9_srtfd.
  DATA lv_jobkey_cnt  TYPE i.

  PERFORM collect_tokens CHANGING lt_srtfd.
  PERFORM sweep_given_tokens USING lt_srtfd pv_dryrun CHANGING lt_stats lv_reap_cnt.
  PERFORM collect_job_keys CHANGING lt_jobkeys.
  PERFORM sweep_given_job_keys USING lt_jobkeys pv_dryrun CHANGING lv_jobkey_cnt.
  PERFORM write_report USING lt_stats pv_dryrun lv_reap_cnt lv_jobkey_cnt.
ENDFORM.

CLASS ltcl_b9 DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS a_age_seconds_pure FOR TESTING.
    METHODS b_budget_aggregation_pure FOR TESTING.
    METHODS c_ttl_eligibility_pure FOR TESTING.
    METHODS d_jobkey_derive_pure FOR TESTING.
ENDCLASS.

CLASS ltcl_b9 IMPLEMENTATION.
  METHOD a_age_seconds_pure.
    DATA lv_from  TYPE timestampl.
    DATA lv_now   TYPE timestampl.
    DATA lv_secs  TYPE i.
    DATA lv_date1 TYPE d VALUE '20260214'.
    DATA lv_time1 TYPE t VALUE '235930'.
    DATA lv_date2 TYPE d VALUE '20260215'.
    DATA lv_time2 TYPE t VALUE '000030'.

    CONVERT DATE lv_date1 TIME lv_time1 INTO TIME STAMP lv_from TIME ZONE 'UTC'.
    CONVERT DATE lv_date2 TIME lv_time2 INTO TIME STAMP lv_now TIME ZONE 'UTC'.
    PERFORM age_seconds USING lv_from lv_now CHANGING lv_secs.

    cl_abap_unit_assert=>assert_equals( act = lv_secs exp = 60
      msg = 'age across a midnight rollover must be 60 seconds' ).
  ENDMETHOD.

  METHOD b_budget_aggregation_pure.
    DATA lt_stats  TYPE tt_b9_stat.
    DATA ls_stat   TYPE ty_b9_stat.
    DATA lv_tokens TYPE i.
    DATA lv_bytes  TYPE i.
    DATA lv_oldest TYPE i.

    ls_stat-age_secs = 100.
    ls_stat-bytes = 40.
    APPEND ls_stat TO lt_stats.
    ls_stat-age_secs = 90000.
    ls_stat-bytes = 10.
    APPEND ls_stat TO lt_stats.

    PERFORM aggregate_budget USING lt_stats CHANGING lv_tokens lv_bytes lv_oldest.

    cl_abap_unit_assert=>assert_equals( act = lv_tokens exp = 2 msg = 'token count must match input rows' ).
    cl_abap_unit_assert=>assert_equals( act = lv_bytes exp = 50 msg = 'bytes must sum every row' ).
    cl_abap_unit_assert=>assert_equals( act = lv_oldest exp = 90000 msg = 'oldest must be the maximum' ).
  ENDMETHOD.

  METHOD c_ttl_eligibility_pure.
    DATA lv_at_ttl   TYPE abap_bool.
    DATA lv_over_ttl TYPE abap_bool.
    DATA lv_boundary TYPE i.
    DATA lv_over     TYPE i.

    lv_boundary = gc_b9_reap_ttl_secs.
    lv_over     = gc_b9_reap_ttl_secs + 1.
    PERFORM mark_eligible USING lv_boundary CHANGING lv_at_ttl.
    PERFORM mark_eligible USING lv_over CHANGING lv_over_ttl.

    cl_abap_unit_assert=>assert_equals( act = lv_at_ttl exp = abap_false msg = 'idle == TTL is not eligible' ).
    cl_abap_unit_assert=>assert_equals( act = lv_over_ttl exp = abap_true msg = 'idle == TTL+1 is eligible' ).
  ENDMETHOD.

  METHOD d_jobkey_derive_pure.
    " SC1/round-4: LCL_PLAIDCL_B12_JOBKEY=>DERIVE is now the one
    " implementation every site shares. A name under 12 characters (never
    " one RUN_ASYNC itself generates; only a hand-scheduled SM37 job) must
    " be refused, not a negative SUBSTRING, and a normal name must give
    " exactly the original inline formula's key: the name's own last 12
    " characters + JOBCOUNT.
    DATA lv_short    TYPE tbtco-jobname VALUE 'SHORTNAME'.
    DATA lv_normal   TYPE tbtco-jobname VALUE 'PLAIDCLB12_A1B2C3D4E5F6'.
    DATA lv_jobcount TYPE tbtco-jobcount VALUE '19265900'.
    DATA lv_id       TYPE indx-srtfd.
    DATA lv_expected TYPE indx-srtfd.

    lv_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = lv_short iv_jobcount = lv_jobcount ).
    cl_abap_unit_assert=>assert_initial( act = lv_id
      msg = 'a job name under 12 characters must be refused, not a negative SUBSTRING' ).

    lv_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = lv_normal iv_jobcount = lv_jobcount ).
    lv_expected = |A1B2C3D4E5F6{ lv_jobcount }|.
    cl_abap_unit_assert=>assert_equals( act = lv_id exp = lv_expected
      msg = |a >=12-character name must give the name's last 12 characters + JOBCOUNT, got [{ lv_id }]| ).
  ENDMETHOD.
ENDCLASS.

CLASS ltcl_b9_db DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL DANGEROUS.
  PRIVATE SECTION.
    DATA mt_ids TYPE tt_b9_srtfd.

    DATA mt_jobkeys TYPE tt_b9_srtfd.
    DATA mt_jobs    TYPE tt_b9v_jobs.

    METHODS teardown.
    METHODS new_id RETURNING VALUE(rv_token) TYPE string.
    METHODS stage
      IMPORTING iv_created  TYPE timestampl
                iv_accessed TYPE timestampl OPTIONAL
                it_rows     TYPE string_table OPTIONAL
      RETURNING VALUE(rv_token) TYPE string.
    " SN4: a random id in the same SHAPE CLASS as a real customer record
    " (short, or 22 characters but not hex) -- never a fixed literal that
    " could collide with one.
    METHODS random_non_token_id
      IMPORTING iv_full_length TYPE abap_bool
      RETURNING VALUE(rv_id)   TYPE indx-srtfd.
    METHODS open_job RETURNING VALUE(rs_job) TYPE ty_b9v_job.
    METHODS zj_key
      IMPORTING is_job        TYPE ty_b9v_job
      RETURNING VALUE(rv_id)  TYPE indx-srtfd.

    METHODS a_fresh_token_not_eligible FOR TESTING.
    METHODS b_backdated_token_eligible FOR TESTING.
    METHODS c_dry_run_never_deletes FOR TESTING.
    METHODS d_live_reap_then_not_found FOR TESTING.
    METHODS e_recent_fetch_blocks_reap FOR TESTING.
    METHODS f_budget_cluster_once FOR TESTING.
    METHODS g_vanished_before_import FOR TESTING.
    METHODS h_non_pc_record_untouched FOR TESTING.
    METHODS i_orphan_job_input_reaped FOR TESTING.
    METHODS j_pc_prefixed_customer_kept FOR TESTING.
    METHODS k_zj_reaped_after_job_ends FOR TESTING.
    METHODS l_zj_live_job_kept FOR TESTING.
    METHODS m_stale_layout_reaped FOR TESTING.
ENDCLASS.

CLASS ltcl_b9_db IMPLEMENTATION.
  METHOD teardown.
    DATA lv_id  TYPE indx-srtfd.
    DATA ls_job TYPE ty_b9v_job.
    LOOP AT mt_ids INTO lv_id.
      DELETE FROM DATABASE indx(zp) ID lv_id.
      DELETE FROM DATABASE indx(zq) ID lv_id.
      DELETE FROM DATABASE indx(za) ID lv_id.
    ENDLOOP.
    LOOP AT mt_jobkeys INTO lv_id.
      DELETE FROM DATABASE indx(zj) ID lv_id.
    ENDLOOP.
    LOOP AT mt_jobs INTO ls_job.
      CALL FUNCTION 'BP_JOB_DELETE' EXPORTING jobname = ls_job-jobname jobcount = ls_job-jobcount
        EXCEPTIONS error_message = 1 OTHERS = 2.
    ENDLOOP.
    CLEAR: mt_ids, mt_jobkeys, mt_jobs.
  ENDMETHOD.

  METHOD new_id.
    DATA lv_id TYPE indx-srtfd.
    CALL FUNCTION 'Z_PLAIDCL_NEW_TOKEN' IMPORTING ev_token = rv_token EXCEPTIONS OTHERS = 1.
    cl_abap_unit_assert=>assert_subrc( exp = 0 act = sy-subrc msg = 'Z_PLAIDCL_NEW_TOKEN failed' ).
    lv_id = rv_token.
    APPEND lv_id TO mt_ids.
  ENDMETHOD.

  METHOD random_non_token_id.
    " Real tokens are exactly PC_ + 19 hex digits (22 characters). A short
    " id is out of shape by length; a full-length one is kept in shape by
    " length but forced non-hex by its last character, both still random
    " per run so neither can be a fixed literal that collides with a real
    " customer record.
    DATA lv_seed TYPE string.
    lv_seed = new_id( ).
    IF iv_full_length = abap_true.
      rv_id = |PC_{ substring( val = lv_seed off = 3 len = 18 ) }Z|.
    ELSE.
      rv_id = |PC_{ substring( val = lv_seed off = 3 len = 6 ) }|.
    ENDIF.
  ENDMETHOD.

  METHOD open_job.
    " 6 bytes -> 12 hex characters, the same width as RUN_ASYNC's random
    " job-name suffix, so a test can rebuild the ZJ key the same way (SC1).
    DATA lv_random TYPE xstring.
    CALL FUNCTION 'GENERATE_SEC_RANDOM'
      EXPORTING length = 6
      IMPORTING random = lv_random
      EXCEPTIONS OTHERS = 1.
    cl_abap_unit_assert=>assert_subrc( exp = 0 act = sy-subrc msg = 'GENERATE_SEC_RANDOM failed' ).
    rs_job-jobname = |ZPLAIDB9_{ lv_random }|.
    CALL FUNCTION 'JOB_OPEN'
      EXPORTING jobname = rs_job-jobname
      IMPORTING jobcount = rs_job-jobcount
      EXCEPTIONS error_message = 1 OTHERS = 2.
    cl_abap_unit_assert=>assert_subrc( exp = 0 act = sy-subrc msg = |JOB_OPEN { rs_job-jobname } failed| ).
    APPEND rs_job TO mt_jobs.
  ENDMETHOD.

  " SC1: the same composite key production uses (jobname's 12-hex suffix +
  " jobcount).
  METHOD zj_key.
    rv_id = lcl_plaidcl_b12_jobkey=>derive( iv_jobname = is_job-jobname iv_jobcount = is_job-jobcount ).
  ENDMETHOD.

  METHOD stage.
    DATA ls_hdr     TYPE ty_plaidcl_stage_hdr.
    DATA ls_ctrl    TYPE ty_plaidcl_stage_ctrl.
    DATA lt_columns TYPE dfies_table.
    DATA ls_col     TYPE dfies.
    DATA lv_id      TYPE indx-srtfd.

    rv_token = new_id( ).
    lv_id = rv_token.
    ls_col-fieldname = 'X'.
    APPEND ls_col TO lt_columns.
    ls_hdr-owner      = sy-uname.
    ls_hdr-status     = `DONE`.
    ls_hdr-created_at = iv_created.
    EXPORT header = ls_hdr columns = lt_columns rows = it_rows TO DATABASE indx(zp) ID lv_id.
    " Every producer writes ctrl; FETCH only updates it. accessed may be initial.
    ls_ctrl-owner    = sy-uname.
    ls_ctrl-accessed = iv_accessed.
    EXPORT ctrl = ls_ctrl TO DATABASE indx(za) ID lv_id.
  ENDMETHOD.

  METHOD a_fresh_token_not_eligible.
    DATA lv_now   TYPE timestampl.
    DATA lv_id    TYPE indx-srtfd.
    DATA ls_stat  TYPE ty_b9_stat.
    DATA lv_found TYPE abap_bool.

    PERFORM now_timestamp CHANGING lv_now.
    lv_id = stage( iv_created = lv_now it_rows = VALUE #( ( `abc` ) ) ).
    PERFORM stat_for_token USING lv_id lv_now CHANGING ls_stat lv_found.

    cl_abap_unit_assert=>assert_equals( act = lv_found exp = abap_true msg = 'a staged token must be found' ).
    cl_abap_unit_assert=>assert_true( act = boolc( ls_stat-age_secs < 10 )
      msg = |a token staged moments ago must be near-zero idle, got { ls_stat-age_secs }s| ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-ttl_exceeded exp = abap_false msg = 'fresh token not eligible' ).
  ENDMETHOD.

  METHOD b_backdated_token_eligible.
    DATA lv_now     TYPE timestampl.
    DATA lv_created TYPE timestampl.
    DATA lv_id      TYPE indx-srtfd.
    DATA ls_stat    TYPE ty_b9_stat.
    DATA lv_found   TYPE abap_bool.

    PERFORM now_timestamp CHANGING lv_now.
    PERFORM far_past_timestamp CHANGING lv_created.
    lv_id = stage( iv_created = lv_created ).
    PERFORM stat_for_token USING lv_id lv_now CHANGING ls_stat lv_found.

    cl_abap_unit_assert=>assert_equals( act = lv_found exp = abap_true msg = 'backdated token must be found' ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-ttl_exceeded exp = abap_true
      msg = 'a token idle since 2020 must be eligible' ).
  ENDMETHOD.

  METHOD c_dry_run_never_deletes.
    DATA lv_created  TYPE timestampl.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lt_stats    TYPE tt_b9_stat.
    DATA lv_reap_cnt TYPE i.
    DATA ls_stat     TYPE ty_b9_stat.
    DATA ls_hdr      TYPE ty_plaidcl_stage_hdr.
    DATA lv_id       TYPE indx-srtfd.
    DATA lv_rc       TYPE i.

    PERFORM far_past_timestamp CHANGING lv_created.
    lv_id = stage( iv_created = lv_created ).
    APPEND lv_id TO lt_ids.

    PERFORM sweep_given_tokens USING lt_ids abap_true CHANGING lt_stats lv_reap_cnt.
    IMPORT header = ls_hdr FROM DATABASE indx(zp) ID lv_id.
    lv_rc = sy-subrc.

    READ TABLE lt_stats INTO ls_stat INDEX 1.
    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 0 msg = 'dry run reaps nothing' ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-ttl_exceeded exp = abap_true msg = 'dry run still reports eligibility' ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-reaped exp = abap_false msg = 'dry run never marks reaped' ).
    cl_abap_unit_assert=>assert_equals( act = lv_rc exp = 0 msg = 'the token must still exist after a dry run' ).
  ENDMETHOD.

  METHOD d_live_reap_then_not_found.
    DATA lv_created  TYPE timestampl.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lt_stats    TYPE tt_b9_stat.
    DATA lv_reap_cnt TYPE i.
    DATA lv_id       TYPE indx-srtfd.
    DATA lv_token    TYPE string.
    DATA lv_rc       TYPE i.

    PERFORM far_past_timestamp CHANGING lv_created.
    lv_token = stage( iv_created = lv_created iv_accessed = lv_created ).
    lv_id = lv_token.
    APPEND lv_id TO lt_ids.

    PERFORM sweep_given_tokens USING lt_ids abap_false CHANGING lt_stats lv_reap_cnt.
    CALL FUNCTION 'Z_PLAIDCL_FETCH' EXPORTING iv_token = lv_token iv_offset = 0
      EXCEPTIONS invalid_input = 1 row_limit_exceeded = 2 not_found = 3 not_ready = 4 run_failed = 5 OTHERS = 6.
    lv_rc = sy-subrc.

    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 1 msg = 'live sweep reaps the idle token' ).
    cl_abap_unit_assert=>assert_equals( act = lv_rc exp = 3
      msg = 'FETCH on a reaped token must raise NOT_FOUND, never restart' ).
  ENDMETHOD.

  METHOD e_recent_fetch_blocks_reap.
    DATA lv_created TYPE timestampl.
    DATA lv_now     TYPE timestampl.
    DATA lv_id      TYPE indx-srtfd.
    DATA lv_token   TYPE string.
    DATA ls_seen    TYPE ty_b9_stat.
    DATA ls_after   TYPE ty_b9_stat.
    DATA lv_found   TYPE abap_bool.
    DATA lv_reaped  TYPE abap_bool.
    DATA lv_rc      TYPE i.

    PERFORM far_past_timestamp CHANGING lv_created.
    lv_token = stage( iv_created = lv_created it_rows = VALUE #( ( `abc` ) ) ).
    lv_id = lv_token.

    PERFORM now_timestamp CHANGING lv_now.
    PERFORM stat_for_token USING lv_id lv_now CHANGING ls_seen lv_found.
    cl_abap_unit_assert=>assert_equals( act = ls_seen-ttl_exceeded exp = abap_true
      msg = 'fixture must start out eligible' ).

    CALL FUNCTION 'Z_PLAIDCL_FETCH' EXPORTING iv_token = lv_token iv_offset = 0
      EXCEPTIONS OTHERS = 1.
    lv_rc = sy-subrc.
    cl_abap_unit_assert=>assert_equals( act = lv_rc exp = 0 msg = 'the in-flight FETCH must succeed' ).

    PERFORM reap_token USING lv_id ls_seen-last_activity CHANGING lv_reaped.
    PERFORM now_timestamp CHANGING lv_now.
    PERFORM stat_for_token USING lv_id lv_now CHANGING ls_after lv_found.

    cl_abap_unit_assert=>assert_equals( act = lv_reaped exp = abap_false
      msg = 'reap_token must back off when a FETCH moved last activity' ).
    cl_abap_unit_assert=>assert_equals( act = ls_after-ttl_exceeded exp = abap_false
      msg = 'TTL runs from the last FETCH, not from creation' ).
  ENDMETHOD.

  METHOD f_budget_cluster_once.
    DATA lv_now    TYPE timestampl.
    DATA lv_small  TYPE indx-srtfd.
    DATA lv_big    TYPE indx-srtfd.
    DATA lv_noise  TYPE string.
    DATA lv_part   TYPE string.
    DATA lt_big    TYPE string_table.
    DATA lt_ids    TYPE tt_b9_srtfd.
    DATA ls_stat   TYPE ty_b9_stat.
    DATA lv_found  TYPE abap_bool.
    DATA lv_rows   TYPE i.
    DATA lv_listed TYPE i.

    PERFORM now_timestamp CHANGING lv_now.
    lv_small = stage( iv_created = lv_now it_rows = VALUE #( ( `abc` ) ( `hello` ) ( `world` ) ) ).
    PERFORM stat_for_token USING lv_small lv_now CHANGING ls_stat lv_found.
    cl_abap_unit_assert=>assert_equals( act = ls_stat-bytes exp = 13 msg = 'bytes = 3 + 5 + 5 row characters' ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-total_rows exp = 3 msg = 'three staged rows' ).

    " Random hex barely compresses, so this cluster spans several INDX rows.
    DO 1000 TIMES.
      CALL FUNCTION 'Z_PLAIDCL_NEW_TOKEN' IMPORTING ev_token = lv_part EXCEPTIONS OTHERS = 1.
      lv_noise = lv_noise && lv_part.
    ENDDO.
    APPEND lv_noise TO lt_big.
    lv_big = stage( iv_created = lv_now it_rows = lt_big ).

    SELECT COUNT( * ) FROM indx INTO lv_rows WHERE relid = 'ZP' AND srtfd = lv_big.
    PERFORM collect_tokens CHANGING lt_ids.
    LOOP AT lt_ids TRANSPORTING NO FIELDS WHERE table_line = lv_big.
      lv_listed = lv_listed + 1.
    ENDLOOP.

    cl_abap_unit_assert=>assert_true( act = boolc( lv_rows > 1 )
      msg = |precondition: the big cluster must span several INDX rows, got { lv_rows }| ).
    cl_abap_unit_assert=>assert_equals( act = lv_listed exp = 1 msg = 'a multi-row cluster is listed once' ).
  ENDMETHOD.

  METHOD g_vanished_before_import.
    DATA lv_now   TYPE timestampl.
    DATA lv_id    TYPE indx-srtfd.
    DATA ls_stat  TYPE ty_b9_stat.
    DATA lv_found TYPE abap_bool.

    PERFORM now_timestamp CHANGING lv_now.
    lv_id = stage( iv_created = lv_now ).
    DELETE FROM DATABASE indx(zp) ID lv_id.
    DELETE FROM DATABASE indx(za) ID lv_id.
    PERFORM stat_for_token USING lv_id lv_now CHANGING ls_stat lv_found.

    cl_abap_unit_assert=>assert_equals( act = lv_found exp = abap_false
      msg = 'a token gone before the read is not found, not a zeroed stat row' ).
  ENDMETHOD.

  METHOD h_non_pc_record_untouched.
    DATA lv_id       TYPE indx-srtfd VALUE 'ZZB9CUSTOMER'.
    DATA lv_payload  TYPE string VALUE `customer data`.
    DATA lv_back     TYPE string.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lt_listed   TYPE tt_b9_srtfd.
    DATA lt_stats    TYPE tt_b9_stat.
    DATA lv_reap_cnt TYPE i.
    DATA lv_rc       TYPE i.

    EXPORT payload = lv_payload TO DATABASE indx(zp) ID lv_id.

    PERFORM collect_tokens CHANGING lt_listed.
    APPEND lv_id TO lt_ids.
    PERFORM sweep_given_tokens USING lt_ids abap_false CHANGING lt_stats lv_reap_cnt.
    IMPORT payload = lv_back FROM DATABASE indx(zp) ID lv_id.
    lv_rc = sy-subrc.
    DELETE FROM DATABASE indx(zp) ID lv_id.

    cl_abap_unit_assert=>assert_equals( act = xsdbool( line_exists( lt_listed[ table_line = lv_id ] ) ) exp = abap_false
      msg = 'collect_tokens must not list a non-PC_ INDX(ZP) record' ).
    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 0 msg = 'a live sweep must not reap it' ).
    cl_abap_unit_assert=>assert_equals( act = lv_rc exp = 0 msg = 'the customer record must survive' ).
    cl_abap_unit_assert=>assert_equals( act = lv_back exp = lv_payload msg = 'and be unchanged' ).
  ENDMETHOD.

  METHOD i_orphan_job_input_reaped.
    DATA lv_id       TYPE indx-srtfd.
    DATA lv_input    TYPE string VALUE `orphan`.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lt_listed   TYPE tt_b9_srtfd.
    DATA lt_stats    TYPE tt_b9_stat.
    DATA lv_reap_cnt TYPE i.
    DATA lv_left     TYPE i.

    lv_id = new_id( ).
    EXPORT input = lv_input TO DATABASE indx(zq) ID lv_id.

    PERFORM collect_tokens CHANGING lt_listed.
    APPEND lv_id TO lt_ids.
    PERFORM sweep_given_tokens USING lt_ids abap_false CHANGING lt_stats lv_reap_cnt.
    SELECT COUNT( * ) FROM indx INTO lv_left WHERE relid = 'ZQ' AND srtfd = lv_id.

    cl_abap_unit_assert=>assert_equals( act = xsdbool( line_exists( lt_listed[ table_line = lv_id ] ) ) exp = abap_true
      msg = 'collect_tokens must list a ZQ-only job input' ).
    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 1 msg = 'an orphaned job input is reaped' ).
    cl_abap_unit_assert=>assert_equals( act = lv_left exp = 0 msg = 'and gone from INDX(ZQ)' ).
  ENDMETHOD.

  METHOD j_pc_prefixed_customer_kept.
    " Neither id is a token: one is short, one is PC_ + 19 characters that
    " are not all uppercase hex (it passes the SQL LIKE, not the shape).
    " SN4: generated per run, never a fixed literal that could collide with
    " an actual customer INDX record such as PC_MYDATA.
    DATA lv_short    TYPE indx-srtfd.
    DATA lv_long     TYPE indx-srtfd.
    DATA lv_payload  TYPE string VALUE `customer data`.
    DATA lv_back1    TYPE string.
    DATA lv_back2    TYPE string.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lt_listed   TYPE tt_b9_srtfd.
    DATA lt_stats    TYPE tt_b9_stat.
    DATA lv_reap_cnt TYPE i.
    DATA lv_rc1      TYPE i.
    DATA lv_rc2      TYPE i.

    lv_short = random_non_token_id( abap_false ).
    lv_long  = random_non_token_id( abap_true ).
    EXPORT payload = lv_payload TO DATABASE indx(zp) ID lv_short.
    EXPORT payload = lv_payload TO DATABASE indx(za) ID lv_long.

    PERFORM collect_tokens CHANGING lt_listed.
    APPEND lv_short TO lt_ids.
    APPEND lv_long TO lt_ids.
    PERFORM sweep_given_tokens USING lt_ids abap_false CHANGING lt_stats lv_reap_cnt.
    IMPORT payload = lv_back1 FROM DATABASE indx(zp) ID lv_short.
    lv_rc1 = sy-subrc.
    IMPORT payload = lv_back2 FROM DATABASE indx(za) ID lv_long.
    lv_rc2 = sy-subrc.
    DELETE FROM DATABASE indx(zp) ID lv_short.
    DELETE FROM DATABASE indx(za) ID lv_long.

    cl_abap_unit_assert=>assert_equals( act = xsdbool( line_exists( lt_listed[ table_line = lv_short ] ) ) exp = abap_false
      msg = |collect_tokens must not list [{ lv_short }]| ).
    cl_abap_unit_assert=>assert_equals( act = xsdbool( line_exists( lt_listed[ table_line = lv_long ] ) ) exp = abap_false
      msg = |collect_tokens must not list a 22-character PC_ id that is not hex [{ lv_long }]| ).
    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 0 msg = 'a live sweep must reap neither' ).
    cl_abap_unit_assert=>assert_equals( act = lv_rc1 exp = 0 msg = |the [{ lv_short }] INDX(ZP) record must survive| ).
    cl_abap_unit_assert=>assert_equals( act = lv_back1 exp = lv_payload msg = 'and be unchanged' ).
    cl_abap_unit_assert=>assert_equals( act = lv_rc2 exp = 0 msg = 'the non-hex PC_ INDX(ZA) record must survive' ).
    cl_abap_unit_assert=>assert_equals( act = lv_back2 exp = lv_payload msg = 'and be unchanged' ).
  ENDMETHOD.

  METHOD k_zj_reaped_after_job_ends.
    DATA ls_jobkey   TYPE ty_plaidcl_job_key.
    DATA lv_id       TYPE indx-srtfd.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lv_reap_cnt TYPE i.
    DATA lv_rc       TYPE i.

    DATA(ls_job) = open_job( ).
    lv_id = zj_key( ls_job ).
    APPEND lv_id TO mt_jobkeys.
    ls_jobkey-jobname  = ls_job-jobname.
    ls_jobkey-jobcount = ls_job-jobcount.
    ls_jobkey-token    = new_id( ).
    EXPORT jobkey = ls_jobkey TO DATABASE indx(zj) ID lv_id.

    " JOB_OPEN alone leaves the job scheduled (P), never run: BP_JOB_DELETE
    " (used by teardown too) purges its TBTCO row outright, the same end
    " state as a job an operator deleted in SM37 without going through
    " Z_PLAIDCL_B12_CANCEL.
    CALL FUNCTION 'BP_JOB_DELETE' EXPORTING jobname = ls_job-jobname jobcount = ls_job-jobcount
      EXCEPTIONS error_message = 1 OTHERS = 2.
    cl_abap_unit_assert=>assert_subrc( exp = 0 act = sy-subrc msg = 'precondition: BP_JOB_DELETE must remove the job' ).

    APPEND lv_id TO lt_ids.
    PERFORM sweep_given_job_keys USING lt_ids abap_false CHANGING lv_reap_cnt.
    IMPORT jobkey = ls_jobkey FROM DATABASE indx(zj) ID lv_id.
    lv_rc = sy-subrc.

    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 1 msg = 'a mapping for a gone job must be reaped' ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lv_rc <> 0 ) msg = 'and gone from INDX(ZJ)' ).
  ENDMETHOD.

  METHOD l_zj_live_job_kept.
    DATA ls_jobkey   TYPE ty_plaidcl_job_key.
    DATA lv_id       TYPE indx-srtfd.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lv_reap_cnt TYPE i.
    DATA lv_rc       TYPE i.

    DATA(ls_job) = open_job( ).
    lv_id = zj_key( ls_job ).
    APPEND lv_id TO mt_jobkeys.
    ls_jobkey-jobname  = ls_job-jobname.
    ls_jobkey-jobcount = ls_job-jobcount.
    ls_jobkey-token    = new_id( ).
    EXPORT jobkey = ls_jobkey TO DATABASE indx(zj) ID lv_id.
    " JOB_OPEN alone leaves TBTCO status P (scheduled, not yet run): the
    " worker may still claim this mapping, so it must not be reaped.

    APPEND lv_id TO lt_ids.
    PERFORM sweep_given_job_keys USING lt_ids abap_false CHANGING lv_reap_cnt.
    IMPORT jobkey = ls_jobkey FROM DATABASE indx(zj) ID lv_id.
    lv_rc = sy-subrc.

    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 0 msg = 'a mapping for a not-yet-run job must survive' ).
    cl_abap_unit_assert=>assert_equals( act = lv_rc exp = 0 msg = 'and stay in INDX(ZJ)' ).
  ENDMETHOD.

  METHOD m_stale_layout_reaped.
    " An upgrade from before a TY_PLAIDCL_STAGE_HDR/CTRL/ROWS type change
    " leaves records in the OLD layout: a plain IMPORT of one dumps
    " CX_SY_IMPORT_MISMATCH_ERROR, and (pre-fix) that took down the WHOLE
    " sweep, so nothing else was ever reaped again. Fabricate exactly
    " that: a different structure under the same object name "header"
    " the real type uses.
    TYPES: BEGIN OF ty_old_layout_probe,
             some_other_field TYPE i,
             another_field    TYPE c LENGTH 40,
           END OF ty_old_layout_probe.
    DATA ls_old      TYPE ty_old_layout_probe.
    DATA lv_stale_id TYPE indx-srtfd.
    DATA lv_good_id  TYPE indx-srtfd.
    DATA lv_now      TYPE timestampl.
    DATA lv_short    TYPE indx-srtfd.
    DATA lv_payload  TYPE string VALUE `customer data`.
    DATA lv_back     TYPE string.
    DATA lt_ids      TYPE tt_b9_srtfd.
    DATA lt_stats    TYPE tt_b9_stat.
    DATA lv_reap_cnt TYPE i.
    DATA ls_stat     TYPE ty_b9_stat.
    DATA lv_rc       TYPE i.

    lv_stale_id = new_id( ).
    ls_old-some_other_field = 42.
    ls_old-another_field    = 'not a TY_PLAIDCL_STAGE_HDR'.
    EXPORT header = ls_old TO DATABASE indx(zp) ID lv_stale_id.

    PERFORM now_timestamp CHANGING lv_now.
    lv_good_id = stage( iv_created = lv_now it_rows = VALUE #( ( `abc` ) ) ).

    " A non-token PC_ customer id: never even a candidate for the sweep.
    lv_short = random_non_token_id( abap_false ).
    EXPORT payload = lv_payload TO DATABASE indx(zp) ID lv_short.

    APPEND lv_stale_id TO lt_ids.
    APPEND lv_good_id TO lt_ids.
    APPEND lv_short TO lt_ids.

    " Reaching this line without a dump is itself part of the proof.
    PERFORM sweep_given_tokens USING lt_ids abap_false CHANGING lt_stats lv_reap_cnt.

    READ TABLE lt_stats WITH KEY srtfd = lv_stale_id INTO ls_stat.
    cl_abap_unit_assert=>assert_subrc( exp = 0 act = sy-subrc msg = 'the stale record must appear in the stats' ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-stale_layout exp = abap_true
      msg = 'must be flagged stale_layout' ).
    cl_abap_unit_assert=>assert_equals( act = ls_stat-reaped exp = abap_true msg = 'must be reaped' ).
    cl_abap_unit_assert=>assert_equals( act = lv_reap_cnt exp = 1
      msg = 'exactly the one incompatible record is reaped this sweep' ).

    IMPORT header = ls_old FROM DATABASE indx(zp) ID lv_stale_id.
    lv_rc = sy-subrc.
    cl_abap_unit_assert=>assert_true( act = xsdbool( lv_rc <> 0 )
      msg = 'the incompatible record must be deleted from INDX(ZP)' ).

    " IV_TOKEN is a STRING: a local call does not convert the C(22) SRTFD.
    CALL FUNCTION 'Z_PLAIDCL_FETCH' EXPORTING iv_token = |{ lv_good_id }| iv_offset = 0
      EXCEPTIONS OTHERS = 1.
    cl_abap_unit_assert=>assert_subrc( exp = 0 act = sy-subrc
      msg = 'a valid current-layout record for another token must be unaffected' ).

    IMPORT payload = lv_back FROM DATABASE indx(zp) ID lv_short.
    lv_rc = sy-subrc.
    DELETE FROM DATABASE indx(zp) ID lv_short.
    cl_abap_unit_assert=>assert_equals( act = lv_rc exp = 0
      msg = 'a non-token PC_ customer id must survive untouched' ).
    cl_abap_unit_assert=>assert_equals( act = lv_back exp = lv_payload msg = 'and be unchanged' ).
  ENDMETHOD.
ENDCLASS.