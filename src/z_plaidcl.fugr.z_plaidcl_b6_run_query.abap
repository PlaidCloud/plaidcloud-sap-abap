*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B6_RUN_QUERY -- remote-enabled, group Z_PLAIDCL.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b6_run_query.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_WORKSPACE) TYPE  STRING DEFAULT 'STANDARD'
*"     VALUE(IV_USERGROUP) TYPE  STRING
*"     VALUE(IV_QUERYNAME) TYPE  STRING
*"     VALUE(IV_MAX_ROWS) TYPE  I DEFAULT 10000
*"     VALUE(IT_SELECTION) TYPE  STRING_TABLE OPTIONAL
*"  EXPORTING
*"     VALUE(EV_LIST_ID) TYPE  STRING
*"     VALUE(EV_ROW_COUNT) TYPE  I
*"     VALUE(EV_COLUMN_COUNT) TYPE  I
*"     VALUE(EV_TRUNCATED) TYPE  BOOLE_D
*"     VALUE(ET_FIELDS) TYPE  STRING_TABLE
*"     VALUE(ET_ROWS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      QUERY_NOT_FOUND
*"      NOT_AUTHORIZED
*"      QUERY_UNAVAILABLE
*"      MAX_ROWS_EXCEEDED
*"      CAPTURE_ABORTED
*"----------------------------------------------------------------------



  DATA lv_msg TYPE c LENGTH 255.
  DATA lv_rc  TYPE i.
  DATA lv_v1  TYPE symsgv.
  DATA lv_v2  TYPE symsgv.
  DATA lv_v3  TYPE symsgv.
  DATA lv_v4  TYPE symsgv.

  CLEAR: ev_list_id, ev_row_count, ev_column_count, ev_truncated, et_fields, et_rows.

  CALL FUNCTION 'Z_PLAIDCL_B6_QUERY_WORKER' DESTINATION 'NONE'
    EXPORTING
      iv_workspace          = iv_workspace
      iv_usergroup          = iv_usergroup
      iv_queryname          = iv_queryname
      iv_max_rows           = iv_max_rows
      it_selection          = it_selection
    IMPORTING
      ev_list_id            = ev_list_id
      ev_row_count          = ev_row_count
      ev_column_count       = ev_column_count
      ev_truncated          = ev_truncated
      et_fields             = et_fields
      et_rows               = et_rows
    EXCEPTIONS
      invalid_input         = 1
      query_not_found       = 2
      not_authorized        = 3
      query_unavailable     = 4
      max_rows_exceeded     = 5
      system_failure        = 6 MESSAGE lv_msg
      communication_failure = 7 MESSAGE lv_msg
      OTHERS                = 8.
  lv_rc = sy-subrc.
  lv_v1 = sy-msgv1.
  lv_v2 = sy-msgv2.
  lv_v3 = sy-msgv3.
  lv_v4 = sy-msgv4.
  CALL FUNCTION 'RFC_CONNECTION_CLOSE'
    EXPORTING
      destination = 'NONE'
    EXCEPTIONS
      OTHERS      = 1.

  CASE lv_rc.
    WHEN 0.
      RETURN.
    WHEN 1.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
    WHEN 2.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING query_not_found.
    WHEN 3.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
    WHEN 4.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING query_unavailable.
    WHEN 5.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING max_rows_exceeded.
    WHEN OTHERS.
      IF lv_msg IS INITIAL.
        lv_msg = |RFC result { lv_rc }|.
      ENDIF.
      lcl_plaidcl_stage=>msg_chunks(
        EXPORTING iv_text = |Query { iv_usergroup }/{ iv_queryname } aborted in its isolated session: { lv_msg }|
        IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING capture_aborted.
  ENDCASE.

ENDFUNCTION.
