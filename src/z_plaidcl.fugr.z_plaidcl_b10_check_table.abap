FUNCTION z_plaidcl_b10_check_table.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TABLE_NAME) TYPE  TABNAME
*"  EXCEPTIONS
*"      NOT_AUTHORIZED
*"      TABLE_NOT_FOUND
*"----------------------------------------------------------------------



  DATA lv_v1 TYPE symsgv.
  DATA lv_v2 TYPE symsgv.
  DATA lv_v3 TYPE symsgv.
  DATA lv_v4 TYPE symsgv.

  DATA(ls_decision) = lcl_b10_auth=>check_table( iv_table_name ).
  IF ls_decision-outcome = lcl_b10_auth=>c_granted.
    RETURN.
  ENDIF.

  IF ls_decision-outcome = lcl_b10_auth=>c_not_found.
    lcl_b10_auth=>to_msgv( EXPORTING iv_text = ls_decision-reason
                           IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING table_not_found.
  ENDIF.

  lcl_b10_auth=>to_msgv( EXPORTING iv_text = |Not authorized. { ls_decision-reason }|
                         IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
  MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.

ENDFUNCTION.
