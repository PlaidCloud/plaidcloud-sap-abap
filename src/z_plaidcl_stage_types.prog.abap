TYPES: BEGIN OF ty_plaidcl_stage_hdr,
         owner      TYPE syuname,
         status     TYPE string,
         reason     TYPE string,
         truncated  TYPE abap_bool,
         created_at TYPE timestampl,
       END OF ty_plaidcl_stage_hdr.

" submit_date/submit_time are sy-datum/sy-uzeit, the clock TBTCO's end
" date and time use, so B12 STATUS subtracts them without a time zone.
TYPES: BEGIN OF ty_plaidcl_stage_ctrl,
         owner       TYPE syuname,
         accessed    TYPE timestampl,
         jobname     TYPE tbtco-jobname,
         jobcount    TYPE tbtco-jobcount,
         submit_date TYPE d,
         submit_time TYPE t,
       END OF ty_plaidcl_stage_ctrl.

TYPES: BEGIN OF ty_plaidcl_job_input,
         program  TYPE programm,
         tcode    TYPE tcode,
         max_rows TYPE i,
       END OF ty_plaidcl_job_input.

" ZJ is keyed by the job name's 12-hex random suffix + TBTCO-JOBCOUNT (20
" characters; INDX-SRTFD is 22, not 8) -- NOT jobcount alone. JOBCOUNT is
" HHMMSS plus 2 digits and is unique only per JOBNAME, so two RUN_ASYNC
" calls in the same second (different job names) would otherwise collide
" on the same jobcount and overwrite each other's mapping. The job step
" rebuilds this same key from GET_JOB_RUNTIME_INFO's own JOBNAME/JOBCOUNT,
" and still compares the full JOBNAME against JOBKEY-JOBNAME below as a
" second check (JOBCOUNT+suffix can in theory still recycle after a job
" is purged).
TYPES: BEGIN OF ty_plaidcl_job_key,
         jobname  TYPE tbtco-jobname,
         jobcount TYPE tbtco-jobcount,
         token    TYPE string,
       END OF ty_plaidcl_job_key.

CLASS lcl_plaidcl_b12_note DEFINITION.
  PUBLIC SECTION.
    " Condenses a B7 field NOTE (Contract 2's 7th ET_FIELDS column) plus
    " an optional short tier tag into a value that always fits DFIES-
    " FIELDTEXT's 60 characters. The actionable part (a drop count, "may
    " be cut") goes first and B7's fixed boilerplate is dropped; the
    " result never splits a token, so a count is never cut mid-way.
    CLASS-METHODS condense_note
      IMPORTING iv_note             TYPE string
                iv_tag              TYPE string OPTIONAL
      RETURNING VALUE(rv_fieldtext) TYPE string.
ENDCLASS.

CLASS lcl_plaidcl_b12_note IMPLEMENTATION.
  METHOD condense_note.
    DATA lv_segments   TYPE string_table.
    DATA lv_segment    TYPE string.
    DATA lv_actionable TYPE string.
    DATA lv_words      TYPE string_table.
    DATA lv_word       TYPE string.
    DATA lv_prev_word  TYPE string.
    DATA lv_word_idx   TYPE i.
    DATA lv_built      TYPE string.
    DATA lv_candidate  TYPE string.

    " B7's two known actionable note shapes (z_plaidcl_b7_run_tcode.abap):
    "   "<N> list line(s) dropped as page heading"                (tier B)
    "   "SALV capture keeps <W> characters and <N> value(s) fill  (tier A)
    "    that width, so they may be cut"
    " A ";"-segment with no digit at all is fixed boilerplate
    " ("positional (classic list capture); no DDIC type available") and
    " carries nothing the caller can act on. Anything else with a digit
    " but neither known shape is kept as-is; the word-wise fill below
    " still guards the 60-character cap without splitting a token.
    SPLIT iv_note AT ';' INTO TABLE lv_segments.
    LOOP AT lv_segments INTO lv_segment.
      lv_segment = condense( lv_segment ).
      IF lv_segment NA '0123456789'.
        CONTINUE.
      ENDIF.
      CLEAR lv_word.
      IF lv_segment CS `list line(s) dropped`.
        SPLIT lv_segment AT ` ` INTO TABLE lv_words.
        READ TABLE lv_words INTO lv_word INDEX 1.
        IF sy-subrc = 0.
          lv_word = |{ lv_word } dropped|.
        ENDIF.
      ELSEIF lv_segment CS `may be cut`.
        SPLIT lv_segment AT ` ` INTO TABLE lv_words.
        LOOP AT lv_words INTO lv_prev_word.
          lv_word_idx = sy-tabix.
          IF lv_prev_word = `value(s)` AND lv_word_idx > 1.
            READ TABLE lv_words INTO lv_prev_word INDEX lv_word_idx - 1.
            IF sy-subrc = 0.
              lv_word = |{ lv_prev_word } may be cut|.
            ENDIF.
            EXIT.
          ENDIF.
        ENDLOOP.
        IF lv_word IS INITIAL.
          lv_word = `may be cut`.
        ENDIF.
      ELSE.
        lv_word = lv_segment.
      ENDIF.
      IF lv_actionable IS INITIAL.
        lv_actionable = lv_word.
      ELSE.
        lv_actionable = |{ lv_actionable }; { lv_word }|.
      ENDIF.
    ENDLOOP.

    " Actionable content first, the tier tag after: fill word by word and
    " stop before 60 characters, so only trailing WORDS (never a split
    " token) can be lost -- if anything is dropped it is the tag, not
    " the count.
    CLEAR lv_words.
    IF lv_actionable IS NOT INITIAL.
      SPLIT lv_actionable AT ` ` INTO TABLE lv_words.
    ENDIF.
    IF iv_tag IS NOT INITIAL.
      APPEND iv_tag TO lv_words.
    ENDIF.
    CLEAR lv_built.
    LOOP AT lv_words INTO lv_word.
      IF lv_built IS INITIAL.
        lv_candidate = lv_word.
      ELSE.
        lv_candidate = |{ lv_built } { lv_word }|.
      ENDIF.
      IF strlen( lv_candidate ) > 60.
        EXIT.
      ENDIF.
      lv_built = lv_candidate.
    ENDLOOP.
    rv_fieldtext = lv_built.
  ENDMETHOD.
ENDCLASS.

CLASS lcl_plaidcl_b12_jobkey DEFINITION.
  PUBLIC SECTION.
    " SC1: JOBCOUNT alone (HHMMSS + 2 digits) is unique only per JOBNAME,
    " so two jobs in the same second would collide on it. The ZJ id is
    " the job name's LAST 12 characters + JOBCOUNT (20 characters; INDX-
    " SRTFD is 22). A name under 12 characters (hand-scheduled via SM37,
    " never one RUN_ASYNC itself generates) has no such suffix: DERIVE
    " refuses it (an initial result), rather than a negative SUBSTRING
    " offset. The one implementation every site (RUN_ASYNC, the worker,
    " CANCEL, CLOSE, B9's sweep, the verify suite) calls, so the shape
    " and the guard live in exactly one place.
    CLASS-METHODS derive
      IMPORTING iv_jobname   TYPE tbtco-jobname
                iv_jobcount  TYPE tbtco-jobcount
      RETURNING VALUE(rv_id) TYPE indx-srtfd.
ENDCLASS.

CLASS lcl_plaidcl_b12_jobkey IMPLEMENTATION.
  METHOD derive.
    DATA lv_suffix TYPE c LENGTH 12.
    IF strlen( iv_jobname ) < 12.
      RETURN.
    ENDIF.
    lv_suffix = substring( val = iv_jobname off = strlen( iv_jobname ) - 12 len = 12 ).
    rv_id = lv_suffix && iv_jobcount.
  ENDMETHOD.
ENDCLASS.