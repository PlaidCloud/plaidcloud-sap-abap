FUNCTION z_plaidcl_new_token.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  EXPORTING
*"     VALUE(EV_TOKEN) TYPE  STRING
*"  EXCEPTIONS
*"      TOKEN_FAILED
*"----------------------------------------------------------------------



  DATA lv_token TYPE string.
  lv_token = lcl_plaidcl_stage=>new_token( ).
  IF lv_token IS INITIAL.
    MESSAGE e001(00) WITH 'GENERATE_SEC_RANDOM returned no random bytes' RAISING token_failed.
  ENDIF.
  ev_token = lv_token.
ENDFUNCTION.
