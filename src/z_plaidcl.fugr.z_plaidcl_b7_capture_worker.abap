*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B7_CAPTURE_WORKER -- remote-enabled, group Z_PLAIDCL.
*&---------------------------------------------------------------------*
* The isolated capture worker (addendum D). Outside a background job B7
* calls this via DESTINATION 'NONE' so the one SUBMIT runs in a throwaway
* session: an uncatchable DYNPRO_SEND_IN_BACKGROUND / DYNPRO_NOT_FOUND /
* MESSAGE-E/A abort in the target report takes down only that session, and
* the caller closes the connection afterwards. The body is
* lcl_b7_tcode_capture=>worker_body; inside a job (B12) B7 runs that same
* body in-process instead (RB1).
*
* SELF-GATING: any S_RFC holder can call this over RFC, so it repeats the
* Contract-1 gate itself -- Z_PLAIDCL_B10_CHECK_PROGRAM, and the S_DEVELOP
* source gate inside read_source -- and re-runs the static classifier, so
* it never SUBMITs a tier-C report even if a caller lies. It is NOT a
* separate wire surface: IT_SELECTION and the row/field wire are B7's.
*
* Deploy note: this is a SECOND function module in group Z_PLAIDCL,
* created from this same source file; flag it Remote-Enabled (TFDIR
* FMODE='R'), by-value params.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b7_capture_worker.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_MAX_ROWS) TYPE  I DEFAULT 10000
*"     VALUE(IT_SELECTION) TYPE  STRING_TABLE OPTIONAL
*"  EXPORTING
*"     VALUE(EV_TIER) TYPE  STRING
*"     VALUE(EV_TIER_LABEL) TYPE  STRING
*"     VALUE(EV_REFUSED) TYPE  BOOLE_D
*"     VALUE(EV_REFUSAL_REASON) TYPE  STRING
*"     VALUE(EV_ROW_COUNT) TYPE  I
*"     VALUE(EV_COLUMN_COUNT) TYPE  I
*"     VALUE(EV_TRUNCATED) TYPE  BOOLE_D
*"     VALUE(EV_SKIPPED_COLUMNS) TYPE  STRING
*"     VALUE(ET_FIELDS) TYPE  STRING_TABLE
*"     VALUE(ET_ROWS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      NOT_AUTHORIZED
*"      MAX_ROWS_EXCEEDED
*"----------------------------------------------------------------------



  DATA lv_v1    TYPE symsgv.
  DATA lv_v2    TYPE symsgv.
  DATA lv_v3    TYPE symsgv.
  DATA lv_v4    TYPE symsgv.
  DATA ls_meta  TYPE ty_b7_meta.
  DATA lv_error TYPE i.
  DATA lv_text  TYPE string.

  CLEAR: ev_tier, ev_tier_label, ev_refused, ev_refusal_reason, ev_row_count,
         ev_column_count, ev_truncated, ev_skipped_columns, et_fields, et_rows.

  lcl_b7_tcode_capture=>worker_body(
    EXPORTING pv_program    = iv_program
              pv_tcode      = iv_tcode
              pv_max_rows   = iv_max_rows
              pt_wire_sel   = it_selection
    IMPORTING es_meta       = ls_meta
              et_fields     = et_fields
              et_rows       = et_rows
              ev_error      = lv_error
              ev_error_text = lv_text ).
  IF lv_error <> 0.
    lcl_b7_tcode_capture=>message_chunks( EXPORTING pv_text = lv_text
                                          IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    CASE lv_error.
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

  ev_tier            = ls_meta-tier.
  ev_tier_label      = ls_meta-tier_label.
  ev_refused         = ls_meta-refused.
  ev_refusal_reason  = ls_meta-refusal_reason.
  ev_row_count       = ls_meta-row_count.
  ev_column_count    = ls_meta-column_count.
  ev_truncated       = ls_meta-truncated.
  ev_skipped_columns = ls_meta-skipped_columns.

ENDFUNCTION.
