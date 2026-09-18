REPORT z_plaidcl_b4_catalog_tcode.
*----------------------------------------------------------------------
* sc-27793 (B4). Interactive front end only. Tcode resolution lives in
* the FM Z_PLAIDCL_B4_CATALOG_TCODE; the write scan and tier live in
* B7's shared engine. Nothing is re-implemented here. Tests:
* z_plaidcl_verify_b1b4.abap and z_plaidcl_b7_verify.abap.
*----------------------------------------------------------------------

PARAMETERS: p_tcode  TYPE tcode,
            p_report TYPE programm.

START-OF-SELECTION.
  DATA lv_found     TYPE abap_bool.
  DATA lv_kind      TYPE string.
  DATA lv_program   TYPE programm.
  DATA lv_prog_kind TYPE string.
  DATA lv_via       TYPE tcode.
  DATA lv_raw       TYPE string.
  DATA lv_res_note  TYPE string.
  DATA lv_readable  TYPE abap_bool.
  DATA lv_lines     TYPE i.
  DATA lv_includes  TYPE i.
  DATA lv_writes    TYPE abap_bool.
  DATA lv_indet     TYPE abap_bool.
  DATA lv_scan_note TYPE string.
  DATA lt_findings  TYPE string_table.
  DATA lv_tier      TYPE string.
  DATA lv_label     TYPE string.
  DATA lv_refused   TYPE abap_bool.
  DATA lv_reason    TYPE string.
  DATA lv_finding   TYPE string.

  CALL FUNCTION 'Z_PLAIDCL_B4_CATALOG_TCODE'
    EXPORTING
      iv_tcode               = p_tcode
      iv_report              = p_report
    IMPORTING
      ev_tcode_found         = lv_found
      ev_tcode_kind          = lv_kind
      ev_program             = lv_program
      ev_program_kind        = lv_prog_kind
      ev_via_tcode           = lv_via
      ev_raw_param           = lv_raw
      ev_resolve_note        = lv_res_note
      ev_source_readable     = lv_readable
      ev_source_lines_seen   = lv_lines
      ev_includes_expanded   = lv_includes
      ev_writes_detected     = lv_writes
      ev_indeterminate       = lv_indet
      ev_scan_note           = lv_scan_note
      et_findings            = lt_findings
      ev_tier                = lv_tier
      ev_tier_label          = lv_label
      ev_tier_refused        = lv_refused
      ev_tier_refusal_reason = lv_reason
    EXCEPTIONS
      invalid_input          = 1
      OTHERS                 = 2.
  IF sy-subrc <> 0.
    MESSAGE ID sy-msgid TYPE 'S' NUMBER sy-msgno
      WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 DISPLAY LIKE 'E'.
  ELSE.
    WRITE: / 'Tcode kind:', lv_kind, / 'Program:', lv_program, lv_prog_kind,
           / 'Resolve note:', lv_res_note,
           / 'Writes detected:', lv_writes, 'Indeterminate:', lv_indet, 'Includes:', lv_includes,
           / 'Scan note:', lv_scan_note,
           / 'Tier:', lv_tier, lv_label, lv_reason.
    LOOP AT lt_findings INTO lv_finding.
      WRITE / lv_finding.
    ENDLOOP.
  ENDIF.