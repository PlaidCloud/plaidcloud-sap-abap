REPORT z_plaidcl_b10_authorization.
*----------------------------------------------------------------------
* B10 live verification of the gate FMs Z_PLAIDCL_B10_CHECK_TABLE,
* _CHECK_PROGRAM and _CHECK_SOURCE, called locally as the CURRENT user.
*
* The gate logic lives only in function group Z_PLAIDCL (lcl_b10_auth in
* z_plaidcl_b10_authorization_fm.abap, with its pure-logic tests beside
* it). This program holds no copy of it.
*
* On A4H the current user is DEVELOPER (SAP_ALL), so a grant here proves
* the wiring only. Refusals here are ones SAP_ALL cannot override: a
* missing object, or a transaction that does not start the program.
* Genuine authorization denials are proven by Z_PLAIDCL_B10_DENY_VERIFY.
*----------------------------------------------------------------------

START-OF-SELECTION.

CLASS ltcl_b10_live DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    TYPES: BEGIN OF ty_result,
             subrc TYPE i,
             text  TYPE string,
           END OF ty_result.

    METHODS run_program
      IMPORTING iv_program       TYPE programm
                iv_tcode         TYPE tcode OPTIONAL
      RETURNING VALUE(rs_result) TYPE ty_result.

    METHODS read_source
      IMPORTING iv_program       TYPE programm
      RETURNING VALUE(rs_result) TYPE ty_result.

    METHODS table_granted              FOR TESTING.
    METHODS missing_table_refused      FOR TESTING.
    METHODS grouped_program_granted    FOR TESTING.
    METHODS tcode_must_start_program   FOR TESTING.
    METHODS missing_program_refused    FOR TESTING.
    METHODS source_granted             FOR TESTING.
    METHODS missing_source_refused     FOR TESTING.
ENDCLASS.

CLASS ltcl_b10_live IMPLEMENTATION.

  " rs_result-subrc: 0 granted, 1 NOT_AUTHORIZED, 2 PROGRAM_NOT_FOUND, 3 other.
  METHOD run_program.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
      EXPORTING
        iv_program        = iv_program
        iv_tcode          = iv_tcode
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
    rs_result-subrc = sy-subrc.
    rs_result-text  = |{ sy-msgv1 }{ sy-msgv2 }{ sy-msgv3 }{ sy-msgv4 }|.
  ENDMETHOD.

  METHOD read_source.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_SOURCE'
      EXPORTING
        iv_program        = iv_program
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
    rs_result-subrc = sy-subrc.
    rs_result-text  = |{ sy-msgv1 }{ sy-msgv2 }{ sy-msgv3 }{ sy-msgv4 }|.
  ENDMETHOD.

  METHOD table_granted.
    DATA lv_table TYPE tabname VALUE 'DD02L'.

    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_TABLE'
      EXPORTING
        iv_table_name   = lv_table
      EXCEPTIONS
        not_authorized  = 1
        table_not_found = 2
        OTHERS          = 3.
    DATA(lv_subrc) = sy-subrc.
    DATA(lv_text) = |{ sy-msgv1 }{ sy-msgv2 }{ sy-msgv3 }{ sy-msgv4 }|.

    cl_abap_unit_assert=>assert_equals(
      act = lv_subrc exp = 0
      msg = |DD02L as { sy-uname }: rc={ lv_subrc } { lv_text }| ).
  ENDMETHOD.

  METHOD missing_table_refused.
    DATA lv_table TYPE tabname VALUE 'ZZZZ_PLAIDCL_NO_SUCH_TABLE'.

    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_TABLE'
      EXPORTING
        iv_table_name   = lv_table
      EXCEPTIONS
        not_authorized  = 1
        table_not_found = 2
        OTHERS          = 3.
    DATA(lv_subrc) = sy-subrc.
    DATA(lv_text) = |{ sy-msgv1 }{ sy-msgv2 }{ sy-msgv3 }{ sy-msgv4 }|.

    cl_abap_unit_assert=>assert_equals(
      act = lv_subrc exp = 2
      msg = |expected TABLE_NOT_FOUND (2): rc={ lv_subrc } { lv_text }| ).
    cl_abap_unit_assert=>assert_char_cp(
      act = lv_text exp = '*ZZZZ_PLAIDCL_NO_SUCH_TABLE*'
      msg = |refusal message must name the table (Contract 3): [{ lv_text }]| ).
  ENDMETHOD.

  METHOD grouped_program_granted.
    " Run by name with an authorization group: S_TCODE SA38 and S_PROGRAM.
    DATA lv_program TYPE programm.

    SELECT SINGLE name FROM trdir
      WHERE secu <> @space
        AND subc = '1'
      INTO @lv_program.
    cl_abap_unit_assert=>assert_not_initial(
      act = lv_program
      msg = 'no program with an authorization group (TRDIR-SECU) on this system' ).

    DATA(ls_result) = run_program( lv_program ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_result-subrc exp = 0
      msg = |{ lv_program } by name as { sy-uname }: rc={ ls_result-subrc } { ls_result-text }| ).
  ENDMETHOD.

  METHOD tcode_must_start_program.
    " SA38 starts SAPMS38M, not a report: SAP cannot run the report "via SA38
    " as a transaction", so neither may the gate, even for SAP_ALL.
    DATA lv_program TYPE programm.

    SELECT SINGLE name FROM trdir
      WHERE secu = @space
        AND subc = '1'
      INTO @lv_program.

    DATA(ls_result) = run_program( iv_program = lv_program iv_tcode = 'SA38' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_result-subrc exp = 1
      msg = |{ lv_program } via SA38 must be NOT_AUTHORIZED (1): rc={ ls_result-subrc } { ls_result-text }| ).
    cl_abap_unit_assert=>assert_char_cp(
      act = ls_result-text exp = '*SA38: transaction SA38 does not start program*'
      msg = |refusal must name the transaction/program mismatch: [{ ls_result-text }]| ).
  ENDMETHOD.

  METHOD missing_program_refused.
    DATA(ls_result) = run_program( 'Z_PLAIDCL_NO_SUCH_PROGRAM' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_result-subrc exp = 2
      msg = |expected PROGRAM_NOT_FOUND (2): rc={ ls_result-subrc } { ls_result-text }| ).
  ENDMETHOD.

  METHOD source_granted.
    DATA(ls_result) = read_source( 'Z_PLAIDCL_B10_AUTHORIZATION' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_result-subrc exp = 0
      msg = |source of Z_PLAIDCL_B10_AUTHORIZATION as { sy-uname }: rc={ ls_result-subrc } { ls_result-text }| ).
  ENDMETHOD.

  METHOD missing_source_refused.
    DATA(ls_result) = read_source( 'Z_PLAIDCL_NO_SUCH_PROGRAM' ).
    cl_abap_unit_assert=>assert_equals(
      act = ls_result-subrc exp = 2
      msg = |expected PROGRAM_NOT_FOUND (2): rc={ ls_result-subrc } { ls_result-text }| ).
    cl_abap_unit_assert=>assert_char_cp(
      act = ls_result-text exp = '*Z_PLAIDCL_NO_SUCH_PROGRAM*'
      msg = |refusal message must name the program (Contract 3): [{ ls_result-text }]| ).
  ENDMETHOD.

ENDCLASS.