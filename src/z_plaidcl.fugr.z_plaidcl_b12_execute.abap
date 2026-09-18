FUNCTION z_plaidcl_b12_execute.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TOKEN) TYPE  STRING
*"----------------------------------------------------------------------



  DATA ls_input   TYPE ty_plaidcl_job_input.
  DATA ls_hdr     TYPE ty_plaidcl_stage_hdr.
  DATA lt_sel     TYPE string_table.
  DATA lt_fields  TYPE string_table.
  DATA lt_rows    TYPE string_table.
  DATA lt_columns TYPE dfies_table.
  DATA lt_parts   TYPE string_table.
  DATA ls_col     TYPE dfies.
  DATA lv_line    TYPE string.
  DATA lv_refused TYPE abap_bool.
  DATA lv_reason  TYPE string.
  DATA lv_id      TYPE indx-srtfd.
  DATA lv_rc      TYPE i.
  DATA lv_row_no  TYPE i.
  DATA lv_tag     TYPE string.
  DATA ls_still_open TYPE ty_plaidcl_stage_ctrl.

  IF lcl_plaidcl_stage=>is_token( iv_token ) = abap_false.
    RETURN.
  ENDIF.
  lv_id = iv_token.
  ls_hdr-owner  = sy-uname.
  ls_hdr-status = `FAILED`.

  IMPORT input = ls_input selection = lt_sel FROM DATABASE indx(zq) ID lv_id.
  lv_rc = sy-subrc.
  IF lv_rc <> 0.
    ls_hdr-reason = |No staged job input for { iv_token } (IMPORT subrc={ lv_rc })|.
  ELSE.
    DELETE FROM DATABASE indx(zq) ID lv_id.

    " SB1: re-gate by the SAME path RUN_ASYNC classified with. A by-tcode
    " job must call B7 with IV_TCODE, never fall back to IV_REPORT: B7's own
    " by-name gate requires S_TCODE SA38, which is stricter than SAP's own
    " tcode start and would wrongly deny a tcode-only user.
    IF ls_input-tcode IS NOT INITIAL.
      CALL FUNCTION 'Z_PLAIDCL_B7_RUN_TCODE'
        EXPORTING
          iv_tcode          = ls_input-tcode
          iv_max_rows       = ls_input-max_rows
          it_selection      = lt_sel
        IMPORTING
          ev_refused        = lv_refused
          ev_refusal_reason = lv_reason
          ev_truncated      = ls_hdr-truncated
          et_fields         = lt_fields
          et_rows           = lt_rows
        EXCEPTIONS
          error_message     = 1
          OTHERS            = 2.
    ELSE.
      CALL FUNCTION 'Z_PLAIDCL_B7_RUN_TCODE'
        EXPORTING
          iv_report         = ls_input-program
          iv_max_rows       = ls_input-max_rows
          it_selection      = lt_sel
        IMPORTING
          ev_refused        = lv_refused
          ev_refusal_reason = lv_reason
          ev_truncated      = ls_hdr-truncated
          et_fields         = lt_fields
          et_rows           = lt_rows
        EXCEPTIONS
          error_message     = 1
          OTHERS            = 2.
    ENDIF.
    lv_rc = sy-subrc.

    IF lv_rc <> 0.
      ls_hdr-reason = |Z_PLAIDCL_B7_RUN_TCODE failed for { ls_input-program }| &&
                      COND string( WHEN ls_input-tcode IS NOT INITIAL THEN | (tcode { ls_input-tcode })| ELSE `` ) &&
                      | (subrc={ lv_rc }): | &&
                      |{ sy-msgv1 }{ sy-msgv2 }{ sy-msgv3 }{ sy-msgv4 }|.
    ELSEIF lv_refused = abap_true.
      ls_hdr-reason = lv_reason.
    ELSE.
      ls_hdr-status = `DONE`.

      " B7 field line: position|fieldname|rollname|datatype|length|decimals|note
      LOOP AT lt_fields INTO lv_line.
        lv_row_no = sy-tabix.
        lt_parts = lcl_plaidcl_codec=>decode_row( lv_line ).
        IF lines( lt_parts ) < 7.
          ls_hdr-status = `FAILED`.
          ls_hdr-reason = |B7 field descriptor { lv_row_no } is malformed: { lv_line }|.
          EXIT.
        ENDIF.
        CLEAR ls_col.
        ls_col-position  = lt_parts[ 1 ].
        ls_col-fieldname = lt_parts[ 2 ].
        ls_col-rollname  = lt_parts[ 3 ].
        ls_col-leng      = lt_parts[ 5 ].
        ls_col-decimals  = lt_parts[ 6 ].
        " DFIES-DATATYPE is a 4-character DDIC type; B7's POSITIONAL is not one.
        CLEAR lv_tag.
        IF strlen( lt_parts[ 4 ] ) > 4.
          ls_col-datatype = 'CHAR'.
          lv_tag          = 'POS'.
        ELSE.
          ls_col-datatype = lt_parts[ 4 ].
        ENDIF.

        " Stage the NOTE for every tier (a dropped-heading count, a
        " cut-value warning): the caller needs it whether or not the
        " column got a DDIC type. LCL_PLAIDCL_B12_NOTE=>CONDENSE_NOTE
        " (Z_PLAIDCL_STAGE_TYPES) fits it into FIELDTEXT's 60-character
        " cap, actionable part first, without ever splitting a token.
        ls_col-fieldtext = lcl_plaidcl_b12_note=>condense_note(
          iv_note = lt_parts[ 7 ] iv_tag = lv_tag ).

        APPEND ls_col TO lt_columns.
      ENDLOOP.

      IF ls_hdr-status = `DONE`.
        LOOP AT lt_rows INTO lv_line.
          lv_row_no = sy-tabix.
          lt_parts = lcl_plaidcl_codec=>decode_row( lv_line ).
          IF lines( lt_parts ) <> lines( lt_columns ).
            ls_hdr-status = `FAILED`.
            ls_hdr-reason = |B7 row { lv_row_no } decodes to { lines( lt_parts ) } values, | &&
                            |expected { lines( lt_columns ) }|.
            EXIT.
          ENDIF.
        ENDLOOP.
      ENDIF.
    ENDIF.
  ENDIF.

  IF ls_hdr-status <> `DONE`.
    CLEAR: lt_columns, lt_rows, ls_hdr-truncated.
  ENDIF.
  GET TIME STAMP FIELD ls_hdr-created_at.

  " CLOSE-while-running / CANCEL race: if the token was closed while this
  " job was capturing (INDX(ZA) is gone), staging a result now would
  " resurrect a ZP nobody owns and nobody will ever FETCH or CLOSE again
  " -- an orphan only B9's 24h TTL would eventually reap. Discard silently;
  " there is no caller left to report a failure to.
  IMPORT ctrl = ls_still_open FROM DATABASE indx(za) ID lv_id.
  IF sy-subrc <> 0.
    RETURN.
  ENDIF.
  EXPORT header = ls_hdr columns = lt_columns rows = lt_rows TO DATABASE indx(zp) ID lv_id.
ENDFUNCTION.
