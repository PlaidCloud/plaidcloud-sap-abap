*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B14_VARIANT_VALUES -- remote-enabled, group Z_PLAIDCL.
*& See Z_PLAIDCL_B14_VARIANTS for the contract.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b14_variant_values.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_REPORT) TYPE  PROGRAMM OPTIONAL
*"     VALUE(IV_VARIANT) TYPE  VARIANT
*"  EXPORTING
*"     VALUE(EV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(ET_SELECTION) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      NOT_AUTHORIZED
*"      VARIANT_NOT_FOUND
*"----------------------------------------------------------------------



  DATA lv_v1       TYPE symsgv.
  DATA lv_v2       TYPE symsgv.
  DATA lv_v3       TYPE symsgv.
  DATA lv_v4       TYPE symsgv.
  DATA lt_params   TYPE ty_b14_params.
  DATA lt_params_l TYPE ty_b14_params_l.
  DATA lv_sap      TYPE string.

  CLEAR: ev_program, et_selection.

  DATA(ls_resolved) = lcl_b14_variants=>resolve( iv_tcode = iv_tcode iv_report = iv_report ).
  IF ls_resolved-error IS INITIAL AND iv_variant IS INITIAL.
    ls_resolved-error = `INVALID_INPUT`.
    ls_resolved-text  = `IV_VARIANT is required.`.
  ENDIF.
  IF ls_resolved-error IS NOT INITIAL.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = ls_resolved-text
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    CASE ls_resolved-error.
      WHEN `NOT_FOUND`.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
      WHEN `NOT_AUTHORIZED`.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
      WHEN OTHERS.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
    ENDCASE.
  ENDIF.
  ev_program = ls_resolved-program.

  CLEAR: sy-msgid, sy-msgv1, sy-msgv2, sy-msgv3, sy-msgv4.
  " VALUTAB is C(45) per value and would cut a longer one silently; VALUTABL is read.
  CALL FUNCTION 'RS_VARIANT_CONTENTS'
    EXPORTING
      report               = ls_resolved-program
      variant              = iv_variant
    TABLES
      valutab              = lt_params
      valutabl             = lt_params_l
    EXCEPTIONS
      variant_non_existent = 1
      variant_obsolete     = 2
      error_message        = 3
      OTHERS               = 4.
  IF sy-subrc <> 0.
    DATA(lv_rc) = sy-subrc.
    IF sy-msgid IS NOT INITIAL.
      MESSAGE ID sy-msgid TYPE 'I' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO lv_sap.
    ENDIF.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = |Variant [{ iv_variant }] of [{ ls_resolved-program }] | &&
                          |{ SWITCH string( lv_rc WHEN 1 THEN `does not exist`
                                                  WHEN 2 THEN `is obsolete`
                                                  ELSE `could not be read` ) }. { lv_sap }|
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING variant_not_found.
  ENDIF.

  DATA(ls_values) = lcl_b14_variants=>encode_values( lt_params_l ).
  IF ls_values-error IS NOT INITIAL.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = ls_values-text
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDIF.
  et_selection = ls_values-rows.

ENDFUNCTION.
