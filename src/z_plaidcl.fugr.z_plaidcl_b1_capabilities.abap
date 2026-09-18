*&---------------------------------------------------------------------*
*& sc-27787 (B1 -- Z_PLAIDCL_B1_CAPABILITIES, RFC wrapper).
*&---------------------------------------------------------------------*
* Thin, remote-enabled FM wrapper around the AUnit-verified logic in
* z_plaidcl_b1_capabilities.abap (REPORT, UNMODIFIED, still live). That
* REPORT proved six live capability checks via forced-failure AUnit
* messages; this file re-declares the SAME checks as ordinary
* class-method logic (no cl_abap_unit_assert anywhere) so an FM body can
* call them and flatten the results onto the wire. Nothing here changes
* what was proven -- it is the identical CALL FUNCTION / SELECT
* sequence per check, just returning data instead of failing a test.
*
* Deploys into the SAME Z_PLAIDCL function group as B5/B6/B7/B8/B12
* (every FM in a group compiles as ONE unit). New names introduced here
* are exactly: LCL_B1_CAPABILITIES (class). All internal logic reuses
* B5's already-live LCL_SQL_SAFETY=>CHECK_IDENTIFIER for the one place
* a caller-supplied table name is embedded in a dynamic RFC_READ_TABLE
* WHERE condition (ET_DDIC_READABLE) -- no duplicated validation logic.
*
* WIRE CONTRACT:
*   - Every ABAP_BOOL-typed EXPORTING field (EV_OP_*, EV_SUPPORTED via
*     ET_DDIC_READABLE rows) crosses RFC as the raw CHAR1 value: 'X' for
*     abap_true, a SINGLE SPACE (' ') for abap_false -- NEVER blank/
*     omitted. A Python caller MUST compare explicitly
*     (`value == 'X'`), never rely on truthiness: a lone space is a
*     non-empty, and therefore truthy, Python string. Same caveat as
*     every other Bn FM in this package.
*   - EV_SQ01_CATALOG_ROW_COUNT is TYPE I (a real integer), not a NUMC/
*     character count, so a zero crosses as the Python int 0 (falsy,
*     correct) rather than a zero-padded digit string (truthy, wrong).
*   - ET_DDIC_READABLE rows are lcl_plaidcl_codec rows (Contract 2),
*     "TABNAME|READABLE". TABNAME is ALWAYS the validated-identifier
*     form (uppercased, `^[A-Z][A-Z0-9_]{0,29}$`, optionally one leading
*     `/NAMESPACE/` segment) or the literal token "(INVALID_NAME)" --
*     never raw, unvalidated caller input. READABLE is 'X' or '' (CT1:
*     a boolean inside a codec row is an explicit flag string, never
*     the raw ABAP_BOOL space character used for EV_OP_* above -- a lone
*     space is easy to lose to a naive trim, '' is not). Decode with the
*     codec, never a plain `split('|')`.
*
* SCOPE: target is SAP_BASIS 816 ABAP Platform, no S4CORE. Every check
* below reads Basis/DDIC catalog tables (RFCSI, CVERS, DD02L) or calls
* Basis-layer FMs (RFC_READ_TABLE, RSAQ_REMOTE_QUERY_CATALOG) -- nothing
* here is or can be a verified result for an ERP business object.
*&---------------------------------------------------------------------*

" ABAP forbids inline type construction (TYPE STANDARD TABLE OF x) in a
" METHODS/FUNCTION signature -- named type, referenced below.
TYPES ty_b1_rfc_db_opt_tab TYPE STANDARD TABLE OF rfc_db_opt WITH DEFAULT KEY.

CLASS lcl_b1_capabilities DEFINITION FINAL.
  PUBLIC SECTION.
    " Platform provenance expects /PLAIDCL/CAPABILITIES to supply this;
    " bump it whenever this FM's wire contract changes.
    CONSTANTS c_package_version TYPE string VALUE '1.0.0'.

    " Splits a WHERE-option string into <=72-char RFC_DB_OPT-TEXT rows
    " (that field's hard DDIC bound) so a caller-supplied identifier
    " long enough to overflow one line never silently truncates the
    " WHERE clause. RFC_READ_TABLE concatenates OPTIONS rows verbatim,
    " so a split can land mid-literal without changing the result.
    CLASS-METHODS append_where_option
      IMPORTING iv_text     TYPE string
      CHANGING  ct_options  TYPE ty_b1_rfc_db_opt_tab.

    CLASS-METHODS get_system_info
      EXPORTING ev_sysid          TYPE sysysid
                ev_saprelease     TYPE string
                ev_kernel_release TYPE string
                ev_host           TYPE string
                ev_dbhost         TYPE string
                ev_dbsys          TYPE string.

    CLASS-METHODS get_basis_component
      EXPORTING ev_release TYPE string
                ev_sp      TYPE string.

    CLASS-METHODS check_rfc_read_table
      RETURNING VALUE(rv_supported) TYPE abap_bool.

    CLASS-METHODS check_sq01_catalog_reachable
      EXPORTING ev_reachable TYPE abap_bool
                ev_row_count TYPE i.

    CLASS-METHODS check_salv_headless
      EXPORTING ev_supported TYPE abap_bool
                ev_note      TYPE string.

    " One "TABNAME|READABLE" row per pt_tables entry -- see file header
    " WIRE CONTRACT for why an embedded pipe can never occur here.
    CLASS-METHODS check_ddic_readable
      IMPORTING pt_tables      TYPE string_table
      RETURNING VALUE(rt_rows) TYPE string_table.
ENDCLASS.

CLASS lcl_b1_capabilities IMPLEMENTATION.

  METHOD append_where_option.
    DATA lv_remaining TYPE string.
    DATA lv_len       TYPE i.
    DATA lv_take      TYPE i.
    lv_remaining = iv_text.
    WHILE strlen( lv_remaining ) > 0.
      lv_len = strlen( lv_remaining ).
      IF lv_len > 72.
        lv_take = 72.
      ELSE.
        lv_take = lv_len.
      ENDIF.
      APPEND VALUE #( text = substring( val = lv_remaining off = 0 len = lv_take ) ) TO ct_options.
      lv_remaining = substring( val = lv_remaining off = lv_take len = lv_len - lv_take ).
    ENDWHILE.
  ENDMETHOD.

  METHOD get_system_info.
    DATA ls_info TYPE rfcsi.
    CALL FUNCTION 'RFC_SYSTEM_INFO'
      IMPORTING rfcsi_export = ls_info.
    ev_sysid          = ls_info-rfcsysid.
    ev_saprelease     = ls_info-rfcsaprl.
    ev_kernel_release = ls_info-rfckernrl.
    ev_host           = ls_info-rfchost.
    ev_dbhost         = ls_info-rfcdbhost.
    ev_dbsys          = ls_info-rfcdbsys.
  ENDMETHOD.

  METHOD get_basis_component.
    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.
    APPEND VALUE #( fieldname = 'RELEASE' )    TO lt_fields.
    APPEND VALUE #( fieldname = 'EXTRELEASE' ) TO lt_fields.
    APPEND VALUE #( text = `COMPONENT = 'SAP_BASIS'` ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'CVERS' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    IF sy-subrc = 0 AND lines( lt_data ) > 0.
      DATA(lt_parts) = VALUE string_table( ).
      SPLIT lt_data[ 1 ]-wa AT '|' INTO TABLE lt_parts.
      ev_release = COND #( WHEN lines( lt_parts ) >= 1 THEN lt_parts[ 1 ] ELSE `` ).
      ev_sp      = COND #( WHEN lines( lt_parts ) >= 2 THEN lt_parts[ 2 ] ELSE `` ).
      CONDENSE: ev_release, ev_sp.
    ENDIF.
  ENDMETHOD.

  METHOD check_rfc_read_table.
    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.
    APPEND VALUE #( fieldname = 'TABNAME' ) TO lt_fields.
    APPEND VALUE #( text = `TABNAME = 'DD02L'` ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD02L' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    rv_supported = xsdbool( sy-subrc = 0 ).
  ENDMETHOD.

  METHOD check_sq01_catalog_reachable.
    " RSAQ_REMOTE_QUERY_CATALOG is NOT itself RFC-enabled (confirmed
    " separately) but IS reachable as a normal internal ABAP call from a
    " program that is itself invoked over RFC/AUnit -- exactly this FM's
    " own calling shape. RN7: this call previously had no EXCEPTIONS at
    " all, so any ABAP message it could raise would have dumped the
    " whole RFC instead of reporting EV_REACHABLE = abap_false, the
    " honest negative this probe exists to report.
    DATA lt_cat TYPE STANDARD TABLE OF rsaqrqcat.
    CALL FUNCTION 'RSAQ_REMOTE_QUERY_CATALOG'
      EXPORTING
        workspace           = 'G'
        generic_queryname   = '*'
        generic_usergroup   = '*'
        generic_funcarea    = '*'
        with_system_objects = 'X'
      TABLES
        querycatalog = lt_cat
      EXCEPTIONS
        error_message = 1
        OTHERS        = 2.
    ev_reachable = xsdbool( sy-subrc = 0 ).
    ev_row_count = COND i( WHEN sy-subrc = 0 THEN lines( lt_cat ) ELSE 0 ).
  ENDMETHOD.

  METHOD check_salv_headless.
    " Capability proven: SALV data CAN be captured headlessly via
    " cl_salv_bs_runtime_info=>set( data = abap_true display = abap_false )
    " BEFORE the display() call. Never re-triggers the separately proven
    " and documented UNCATCHABLE DYNPRO_SEND_IN_BACKGROUND abort path --
    " this exact sequence (runtime-info mode set first) is the one shown
    " NOT to hit it.
    cl_salv_bs_runtime_info=>set( display = abap_false metadata = abap_false data = abap_true ).
    SELECT * FROM spfli INTO TABLE @DATA(lt_spfli) UP TO 3 ROWS.

    TRY.
        cl_salv_table=>factory(
          IMPORTING r_salv_table = DATA(lo_salv)
          CHANGING  t_table      = lt_spfli ).
        lo_salv->display( ).
        ev_note = 'display() returned without the uncatchable abort (runtime-info mode active). '.
      CATCH cx_root INTO DATA(lx).
        ev_note = |display() raised { lx->get_text( ) } | &&
                  |(caught -- unexpected, this class of abort is normally uncatchable). |.
    ENDTRY.

    DATA lv_rows TYPE i.
    TRY.
        cl_salv_bs_runtime_info=>get_data_ref( IMPORTING r_data = DATA(lr_data) ).
        IF lr_data IS BOUND.
          FIELD-SYMBOLS <t> TYPE ANY TABLE.
          ASSIGN lr_data->* TO <t>.
          lv_rows = lines( <t> ).
        ENDIF.
        ev_note = ev_note && |get_data_ref rows={ lv_rows }|.
      CATCH cx_root INTO DATA(lx2).
        ev_note = ev_note && |get_data_ref raised { lx2->get_text( ) }|.
    ENDTRY.
    cl_salv_bs_runtime_info=>clear_all( ).

    " Derived from the actual captured row count, never hardcoded --
    " ev_supported = X only when data was genuinely captured headlessly.
    ev_supported = xsdbool( lv_rows > 0 ).
  ENDMETHOD.

  METHOD check_ddic_readable.
    LOOP AT pt_tables INTO DATA(lv_tab).
      DATA(lv_valid) = abap_true.
      TRY.
          lcl_b5_sql=>check_identifier( iv_name = lv_tab iv_code = `INVALID_NAME` iv_allow_ns = abap_true ).
        CATCH lcx_b5.
          lv_valid = abap_false.
      ENDTRY.

      IF lv_valid = abap_false.
        APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table( ( `(INVALID_NAME)` ) ( `` ) ) ) TO rt_rows.
        CONTINUE.
      ENDIF.

      DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
      DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
      DATA lt_data    TYPE STANDARD TABLE OF tab512.
      CLEAR: lt_fields, lt_options, lt_data.
      APPEND VALUE #( fieldname = 'TABNAME' ) TO lt_fields.
      " A namespaced identifier (up to 62 chars once /NAMESPACE/ is
      " included) can build a WHERE text over the RFC_DB_OPT-TEXT C(72)
      " bound -- append_where_option splits it across lines instead of
      " letting RFC_READ_TABLE silently truncate the literal.
      append_where_option(
        EXPORTING iv_text    = |TABNAME = '{ to_upper( lv_tab ) }'|
        CHANGING  ct_options = lt_options ).
      CALL FUNCTION 'RFC_READ_TABLE'
        EXPORTING query_table = 'DD02L' delimiter = '|' rowcount = 1
        TABLES options = lt_options fields = lt_fields data = lt_data
        EXCEPTIONS OTHERS = 7.
      DATA(lv_readable) = xsdbool( sy-subrc = 0 AND lines( lt_data ) > 0 ).
      DATA(lv_readable_flag) = COND string( WHEN lv_readable = abap_true THEN `X` ELSE `` ).
      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table( ( to_upper( lv_tab ) ) ( lv_readable_flag ) ) ) TO rt_rows.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& THE FUNCTION MODULE ITSELF.
*&
*& Remote-enabled (RFC). Deploys as Z_PLAIDCL_B1_CAPABILITIES inside the
*& live Z_PLAIDCL function group. Signature is INLINE between the
*& FUNCTION name and the terminating period -- the classic *" Local
*& Interface: comment block PUTs with an HTTP 400 and then activates
*& "successfully" on an empty module; see z_plaidcl_ping.abap.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b1_capabilities.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IT_CHECK_TABLES) TYPE  STRING_TABLE OPTIONAL
*"  EXPORTING
*"     VALUE(EV_PACKAGE_VERSION) TYPE  STRING
*"     VALUE(EV_SYSID) TYPE  SYSYSID
*"     VALUE(EV_SAPRELEASE) TYPE  STRING
*"     VALUE(EV_KERNEL_RELEASE) TYPE  STRING
*"     VALUE(EV_HOST) TYPE  STRING
*"     VALUE(EV_DBHOST) TYPE  STRING
*"     VALUE(EV_DBSYS) TYPE  STRING
*"     VALUE(EV_BASIS_RELEASE) TYPE  STRING
*"     VALUE(EV_BASIS_SP) TYPE  STRING
*"     VALUE(EV_OP_RFC_READ_TABLE) TYPE  BOOLE_D
*"     VALUE(EV_OP_SQ01_CATALOG) TYPE  BOOLE_D
*"     VALUE(EV_SQ01_CATALOG_ROW_COUNT) TYPE  I
*"     VALUE(EV_OP_SALV_HEADLESS) TYPE  BOOLE_D
*"     VALUE(EV_SALV_HEADLESS_NOTE) TYPE  STRING
*"     VALUE(ET_DDIC_READABLE) TYPE  STRING_TABLE
*"----------------------------------------------------------------------



  CLEAR: ev_package_version, ev_sysid, ev_saprelease, ev_kernel_release, ev_host, ev_dbhost, ev_dbsys,
         ev_basis_release, ev_basis_sp, ev_op_rfc_read_table, ev_op_sq01_catalog,
         ev_sq01_catalog_row_count, ev_op_salv_headless, ev_salv_headless_note,
         et_ddic_readable.

  ev_package_version = lcl_b1_capabilities=>c_package_version.

  lcl_b1_capabilities=>get_system_info(
    IMPORTING ev_sysid          = ev_sysid
              ev_saprelease     = ev_saprelease
              ev_kernel_release = ev_kernel_release
              ev_host           = ev_host
              ev_dbhost         = ev_dbhost
              ev_dbsys          = ev_dbsys ).

  lcl_b1_capabilities=>get_basis_component(
    IMPORTING ev_release = ev_basis_release
              ev_sp      = ev_basis_sp ).

  ev_op_rfc_read_table = lcl_b1_capabilities=>check_rfc_read_table( ).

  lcl_b1_capabilities=>check_sq01_catalog_reachable(
    IMPORTING ev_reachable = ev_op_sq01_catalog
              ev_row_count = ev_sq01_catalog_row_count ).

  lcl_b1_capabilities=>check_salv_headless(
    IMPORTING ev_supported = ev_op_salv_headless
              ev_note      = ev_salv_headless_note ).

  DATA(lt_check) = it_check_tables.
  IF lt_check IS INITIAL.
    lt_check = VALUE string_table( ( `DD02L` ) ( `DD03L` ) ( `DD04T` ) ( `DD09L` ) ).
  ENDIF.
  et_ddic_readable = lcl_b1_capabilities=>check_ddic_readable( lt_check ).

ENDFUNCTION.

*&---------------------------------------------------------------------*
*& CT1 codec regression: ET_DDIC_READABLE rows must be lcl_plaidcl_codec
*& rows, not a raw pipe join, and a false READABLE flag must decode to
*& an EMPTY string, never the raw ABAP_BOOL space character. Local class
*& logic only -- no RFC, no repository write, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b1fm_codec DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS readable_flag_is_x_or_empty FOR TESTING.
ENDCLASS.

CLASS ltcl_b1fm_codec IMPLEMENTATION.
  METHOD readable_flag_is_x_or_empty.
    DATA(lv_row_true)  = lcl_plaidcl_codec=>encode_row( VALUE string_table( ( `DD02L` ) ( `X` ) ) ).
    DATA(lv_row_false) = lcl_plaidcl_codec=>encode_row( VALUE string_table( ( `ZZZPLAIDCLNOPE` ) ( `` ) ) ).

    cl_abap_unit_assert=>assert_equals( act = lv_row_true exp = `DD02L|X` msg = |row: [{ lv_row_true }]| ).
    cl_abap_unit_assert=>assert_equals( act = lv_row_false exp = `ZZZPLAIDCLNOPE|` msg = |row: [{ lv_row_false }]| ).

    DATA(lt_decoded_false) = lcl_plaidcl_codec=>decode_row( lv_row_false ).
    cl_abap_unit_assert=>assert_equals( act = lines( lt_decoded_false ) exp = 2
      msg = |decode must still yield 2 fields for an empty READABLE: [{ lv_row_false }]| ).
    cl_abap_unit_assert=>assert_equals( act = lt_decoded_false[ 2 ] exp = ``
      msg = |CT1: a false READABLE flag must decode to an EMPTY string, never a single space: [{ lv_row_false }]| ).
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& VERIFICATION CHECKLIST (mechanical pass once the system is usable).
*& NOT activated or run this session -- the trial pod never finished
*& booting (node ephemeral-storage eviction loop pulling the 23.8GB
*& image; see this session's own report for detail). Static-only pass:
*& syntax/landmine self-review done, nothing executed on a kernel.
*&
*& Deploy:
*&   source scripts/adt.sh; adt_init
*&   adt_deploy_fm Z_PLAIDCL Z_PLAIDCL_B1_CAPABILITIES \
*&     src/z_plaidcl_b1_capabilities_fm.abap "B1 capabilities probe (RFC)"
*&   Confirm put=200 AND activationExecuted="true" with ZERO messages
*&   (an empty-module false-pass looks identical to success on put/
*&   activation status alone -- re-GET the source afterward if in doubt,
*&   same caution as every other Bn FM in this package).
*&
*& 1. Call with IT_CHECK_TABLES empty (defaults to DD02L/DD03L/DD04T/
*&    DD09L). EXPECT: EV_PACKAGE_VERSION = "1.0.0"; EV_SYSID/
*&    EV_SAPRELEASE/EV_KERNEL_RELEASE/EV_HOST/
*&    EV_DBHOST/EV_DBSYS all non-blank; EV_BASIS_RELEASE non-blank
*&    (e.g. "816"); EV_OP_RFC_READ_TABLE = 'X'; EV_OP_SQ01_CATALOG = 'X'
*&    with EV_SQ01_CATALOG_ROW_COUNT >= 0; EV_OP_SALV_HEADLESS = 'X';
*&    ET_DDIC_READABLE has 4 rows, all "TABNAME|X" (every one of those
*&    four catalog tables is always readable on a live Basis system).
*& 2. Call with IT_CHECK_TABLES = ('ZZZPLAIDCLNOPE'). EXPECT: a row
*&    "ZZZPLAIDCLNOPE|<space>" (readable=abap_false, not an exception --
*&    a table that doesn't exist is a normal negative result here).
*& 3. Call with IT_CHECK_TABLES containing an injection-shaped name
*&    (e.g. "DD02L' OR '1'='1"). EXPECT: a row "(INVALID_NAME)|<space>"
*&    -- LCL_SQL_SAFETY=>CHECK_IDENTIFIER (B5's, reused unqualified)
*&    rejects it before it ever reaches a dynamic WHERE-option string.
*& 4. Group-level activation check: confirm B5/B6/B7/B8/B12 (GET 200 on
*&    each) are unchanged after this FM lands in the same compile unit.
*&
*& NOT verifiable on this SAP_BASIS 816, no-S4CORE trial system: nothing
*& here touches ERP business data: every check is Basis/DDIC-layer
*& (RFCSI, CVERS, DD02L, SQ01 catalog, SALV) by construction, same scope
*& note as the REPORT this file wraps.
*&---------------------------------------------------------------------*
