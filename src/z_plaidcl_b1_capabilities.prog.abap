REPORT z_plaidcl_b1_capabilities.
*----------------------------------------------------------------------
* sc-27787 (B1 /PLAIDCL/CAPABILITIES).
* Reports version/release/supported-ops from the RUNNING kernel, to
* feed the P1 capability mechanism. Every value below is read live
* from this system -- nothing hardcoded.
*----------------------------------------------------------------------

START-OF-SELECTION.
  " no-op interactively; ltcl_b1 drives every check.

CLASS ltcl_b1 DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS:
      a_system_info_and_release FOR TESTING,
      b_basis_component_release FOR TESTING,
      c_supported_op_rfc_read_table FOR TESTING,
      d_supported_op_ddic_metadata FOR TESTING,
      e_supported_op_sq01_catalog FOR TESTING,
      f_supported_op_salv_headless FOR TESTING.
ENDCLASS.

CLASS ltcl_b1 IMPLEMENTATION.

  METHOD a_system_info_and_release.
    DATA ls_info TYPE rfcsi.
    CALL FUNCTION 'RFC_SYSTEM_INFO'
      IMPORTING rfcsi_export = ls_info.
    DATA(lv_msg) =
      |sysid={ ls_info-rfcsysid } | &&
      |saprelease={ ls_info-rfcsaprl } | &&
      |host={ ls_info-rfchost } | &&
      |dbhost={ ls_info-rfcdbhost } | &&
      |dbsys={ ls_info-rfcdbsys } | &&
      |kernel_release={ ls_info-rfckernrl } | &&
      |ipaddr={ ls_info-rfcipaddr } | &&
      |chartype={ ls_info-rfcchartyp }|.
    cl_abap_unit_assert=>assert_not_initial( act = ls_info-rfcsysid msg = |A: system id must not be initial: { lv_msg }| ).
    cl_abap_unit_assert=>assert_not_initial( act = ls_info-rfcsaprl msg = |A: SAP_BASIS release must not be initial: { lv_msg }| ).
  ENDMETHOD.

  METHOD b_basis_component_release.
    " CVERS: installed software components and their release/SP level.
    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.
    APPEND VALUE #( fieldname = 'COMPONENT' )  TO lt_fields.
    APPEND VALUE #( fieldname = 'RELEASE' )    TO lt_fields.
    APPEND VALUE #( fieldname = 'EXTRELEASE' ) TO lt_fields.
    APPEND VALUE #( text = `COMPONENT = 'SAP_BASIS' OR COMPONENT = 'SAP_ABA'` ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'CVERS' delimiter = '|' rowcount = 10
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    DATA(lv_subrc) = sy-subrc.
    DATA(lv_msg) = |subrc={ lv_subrc } rows={ lines( lt_data ) }: |.
    LOOP AT lt_data INTO DATA(ls_row).
      lv_msg = lv_msg && |[{ ls_row-wa }] |.
    ENDLOOP.
    cl_abap_unit_assert=>assert_equals( act = lv_subrc exp = 0 msg = |B: RFC_READ_TABLE on CVERS must succeed: { lv_msg }| ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lines( lt_data ) > 0 )
      msg = |B: CVERS must report at least SAP_BASIS on any ABAP system: { lv_msg }| ).
  ENDMETHOD.

  METHOD c_supported_op_rfc_read_table.
    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.
    APPEND VALUE #( fieldname = 'TABNAME' ) TO lt_fields.
    APPEND VALUE #( text = `TABNAME = 'DD02L'` ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD02L' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    DATA(lv_subrc) = sy-subrc.
    cl_abap_unit_assert=>assert_equals( act = lv_subrc exp = 0 msg =
      |C: op=RFC_READ_TABLE supported={ xsdbool( lv_subrc = 0 ) } subrc={ lv_subrc }| ).
  ENDMETHOD.

  METHOD d_supported_op_ddic_metadata.
    DATA(lv_msg) = ``.
    DATA lt_readable TYPE STANDARD TABLE OF abap_bool.
    LOOP AT VALUE string_table( ( `DD02L` ) ( `DD03L` ) ( `DD04T` ) ( `DD09L` ) ) INTO DATA(lv_tab).
      DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
      DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
      DATA lt_data    TYPE STANDARD TABLE OF tab512.
      CLEAR: lt_fields, lt_options, lt_data.
      DATA(lv_tabname) = CONV dd02l-tabname( lv_tab ).
      CALL FUNCTION 'RFC_READ_TABLE'
        EXPORTING query_table = lv_tabname delimiter = '|' rowcount = 1
        TABLES options = lt_options fields = lt_fields data = lt_data
        EXCEPTIONS OTHERS = 7.
      DATA(lv_readable) = xsdbool( sy-subrc = 0 ).
      APPEND lv_readable TO lt_readable.
      lv_msg = lv_msg && |{ lv_tab }_readable={ lv_readable } |.
    ENDLOOP.
    LOOP AT lt_readable INTO DATA(lv_flag).
      cl_abap_unit_assert=>assert_true( act = lv_flag
        msg = |D: op=DDIC_METADATA every core DDIC catalog table must be readable: { lv_msg }| ).
    ENDLOOP.
  ENDMETHOD.

  METHOD e_supported_op_sq01_catalog.
    " RSAQ_REMOTE_QUERY_CATALOG is NOT itself RFC-enabled (confirmed
    " separately), but is reachable as a normal internal call from a
    " program that IS invoked over RFC/AUnit -- which is exactly the
    " capability B3 depends on. Prove that path here.
    DATA lt_cat TYPE STANDARD TABLE OF rsaqrqcat.
    DATA(lv_supported) = abap_true.
    TRY.
        CALL FUNCTION 'RSAQ_REMOTE_QUERY_CATALOG'
          EXPORTING
            workspace           = 'G'
            generic_queryname   = '*'
            generic_usergroup   = '*'
            generic_funcarea    = '*'
            with_system_objects = 'X'
          TABLES
            querycatalog = lt_cat.
      CATCH cx_root.
        lv_supported = abap_false.
    ENDTRY.
    cl_abap_unit_assert=>assert_true( act = lv_supported msg =
      |E: op=SQ01_CATALOG_VIA_INTERNAL_CALL must be reachable from an RFC/AUnit-invoked program | &&
      |(RSAQ_REMOTE_QUERY_CATALOG itself is NOT RFC-enabled) global_area_rows={ lines( lt_cat ) }| ).
  ENDMETHOD.

  METHOD f_supported_op_salv_headless.
    " Not re-triggering the crash here (already proven and documented
    " separately: cl_salv_table=>display() raises the UNCATCHABLE
    " DYNPRO_SEND_IN_BACKGROUND abort under RFC/AUnit). The supported
    " capability is: SALV data CAN be captured headlessly via
    " cl_salv_bs_runtime_info=>set( data = abap_true display = abap_false )
    " BEFORE the display() call -- never by wrapping display() in
    " TRY/CATCH, which does not stop the abort.
    cl_salv_bs_runtime_info=>set( display = abap_false metadata = abap_false data = abap_true ).
    DATA lt_spfli TYPE STANDARD TABLE OF spfli.
    SELECT * FROM spfli INTO TABLE lt_spfli UP TO 3 ROWS.
    DATA(lv_msg) = ``.
    TRY.
        cl_salv_table=>factory(
          IMPORTING r_salv_table = DATA(lo_salv)
          CHANGING  t_table      = lt_spfli ).
        lo_salv->display( ).
        lv_msg = 'display() returned without the uncatchable abort (runtime-info mode active). '.
      CATCH cx_root INTO DATA(lx).
        lv_msg = |display() raised { lx->get_text( ) } (caught -- unexpected, this class of abort is normally uncatchable). |.
    ENDTRY.
    DATA lv_rows TYPE i.
    DATA lr_data TYPE REF TO data.
    TRY.
        cl_salv_bs_runtime_info=>get_data_ref( IMPORTING r_data = lr_data ).
        IF lr_data IS BOUND.
          FIELD-SYMBOLS <t> TYPE ANY TABLE.
          ASSIGN lr_data->* TO <t>.
          lv_rows = lines( <t> ).
        ENDIF.
        lv_msg = lv_msg && |get_data_ref rows={ lv_rows }|.
      CATCH cx_root INTO DATA(lx2).
        lv_msg = lv_msg && |get_data_ref raised { lx2->get_text( ) }|.
    ENDTRY.
    cl_salv_bs_runtime_info=>clear_all( ).
    cl_abap_unit_assert=>assert_true( act = xsdbool( lr_data IS BOUND )
      msg = |F: op=SALV_HEADLESS_CAPTURE must bind a data ref via cl_salv_bs_runtime_info: { lv_msg }| ).
    cl_abap_unit_assert=>assert_equals( act = lv_rows exp = lines( lt_spfli )
      msg = |F: captured row count must match the selected row count: { lv_msg }| ).
  ENDMETHOD.

ENDCLASS.