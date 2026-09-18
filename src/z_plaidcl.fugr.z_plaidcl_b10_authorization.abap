*&---------------------------------------------------------------------*
*& B10 -- SAP authorization enforcement for the shared RFC technical user
*& (plan section 5c). Function group Z_PLAIDCL.
*&
*& "Match SAP's own checks": every path checks what SAP itself checks for
*& the same action, no stricter and no looser.
*&   table display     VIEW_AUTHORITY_CHECK 'S' (S_TABU_NAM or S_TABU_DIS),
*&                     the call RFC_READ_TABLE and SE16 make
*&   run by name       S_TCODE SA38 (+ S_PROGRAM SUBMIT when TRDIR-SECU set),
*&                     what SA38 requires
*&   run by tcode      report transactions only (TSTC-CINFO X'80', no start
*&                     variant or parameters): AUTHORITY_CHECK_TCODE (S_TCODE
*&                     + the tcode's TSTCA object) (+ S_PROGRAM SUBMIT when
*&                     TRDIR-SECU set)
*&   source read       S_DEVELOP display, what SE38 display requires
*&                     (RS_ACCESS_PERMISSION): FUGR <group> for function-
*&                     group code, CLAS/INTF/ENHO <name> for class, interface
*&                     and enhancement code, else PROG <name>; blank DEVCLASS
*&                     and P_GROUP are not checked
*&
*& This source is the single home of B10 logic:
*&   lcl_b10_auth=>rules      the ONE declaration of every authorization
*&                            object, field and fixed value, per gate path
*&   lcl_b10_auth=>check      the only AUTHORITY-CHECK statement; takes its
*&                            IDs and fixed values from rules, refuses an
*&                            object or caller value the path does not declare
*&   lcl_b10_auth=>decide     the only place a decision is made; no check
*&                            run means DENIED, so a zero-check grant is
*&                            impossible by construction
*&   Z_PLAIDCL_B10_AUTHORIZATION (remote) returns rules as codec rows
*& Z_PLAIDCL_B10_CHECK_TABLE / _CHECK_PROGRAM / _CHECK_SOURCE
*& (z_plaidcl_b10_gate_fm.abap) are thin FMs over the class.
*&
*& ACTIVATION ORDER: the gate FMs reference lcl_b10_auth, and a local
*& class must be defined before it is used. Function-group includes
*& compile in creation order, so THIS FM must exist in the group before
*& the gate FMs are created (it already does on A4H).
*&
*& Deliberately no RFC_READ_TABLE for DD02L / TDDAT / TRDIR / TADIR / TSTC:
*& it runs its own table authorization check, so a restricted technical
*& user would get "not found" instead of a real authorization decision.
*& No S_TABU_CLI: that is SAP's cross-client MAINTENANCE object, and SAP
*& does not require it to display a table.
*&---------------------------------------------------------------------*

TYPES ty_b10_authval TYPE c LENGTH 40.
TYPES ty_b10_path    TYPE c LENGTH 8.

TYPES: BEGIN OF ty_b10_rule,
         path         TYPE ty_b10_path,
         object       TYPE xuobject,
         field        TYPE xufield,
         fixed_value  TYPE ty_b10_authval,   " initial = supplied by the caller
         dummy_if_blank TYPE abap_bool,      " blank value = field not checked, as SAP does
         value_hint   TYPE string,
         applies_when TYPE string,
         purpose      TYPE string,
       END OF ty_b10_rule,
       ty_b10_rules TYPE STANDARD TABLE OF ty_b10_rule WITH EMPTY KEY.

TYPES: BEGIN OF ty_b10_fieldval,
         field TYPE xufield,
         value TYPE ty_b10_authval,
       END OF ty_b10_fieldval,
       ty_b10_fieldvals TYPE STANDARD TABLE OF ty_b10_fieldval WITH EMPTY KEY.

TYPES: BEGIN OF ty_b10_check,
         label TYPE string,
         rc    TYPE i,
       END OF ty_b10_check,
       ty_b10_checks TYPE STANDARD TABLE OF ty_b10_check WITH EMPTY KEY.

TYPES: BEGIN OF ty_b10_decision,
         outcome TYPE string,
         reason  TYPE string,
         checks  TYPE string_table,   " every check run, "<label> rc=<n>"
       END OF ty_b10_decision.

CLASS lcl_b10_auth DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_s_tabu_nam TYPE xuobject VALUE 'S_TABU_NAM'.
    CONSTANTS c_s_tabu_dis TYPE xuobject VALUE 'S_TABU_DIS'.
    CONSTANTS c_s_tcode    TYPE xuobject VALUE 'S_TCODE'.
    CONSTANTS c_s_program  TYPE xuobject VALUE 'S_PROGRAM'.
    CONSTANTS c_s_develop  TYPE xuobject VALUE 'S_DEVELOP'.
    " Not an authorization object: the declaration row for the object SE93
    " maintains per transaction, which AUTHORITY_CHECK_TCODE checks.
    CONSTANTS c_tstca      TYPE xuobject VALUE 'TSTCA'.

    CONSTANTS c_path_table    TYPE ty_b10_path VALUE 'TABLE'.
    CONSTANTS c_path_by_name  TYPE ty_b10_path VALUE 'BY_NAME'.
    CONSTANTS c_path_by_tcode TYPE ty_b10_path VALUE 'BY_TCODE'.
    CONSTANTS c_path_run      TYPE ty_b10_path VALUE 'RUN'.
    CONSTANTS c_path_source   TYPE ty_b10_path VALUE 'SOURCE'.

    CONSTANTS c_granted   TYPE string VALUE 'GRANTED'.
    CONSTANTS c_denied    TYPE string VALUE 'DENIED'.
    CONSTANTS c_not_found TYPE string VALUE 'NOT_FOUND'.

    " Stand-in return code for a check that never reached AUTHORITY-CHECK
    " because the object or caller values do not match rules. Never 0.
    CONSTANTS c_undeclared TYPE i VALUE 99.

    CONSTANTS c_delimiter TYPE c LENGTH 1 VALUE '|'.

    CLASS-METHODS rules
      RETURNING VALUE(rt_rules) TYPE ty_b10_rules.

    CLASS-METHODS rules_wire
      IMPORTING it_rules       TYPE ty_b10_rules
      RETURNING VALUE(rt_rows) TYPE string_table.

    CLASS-METHODS check
      IMPORTING iv_path         TYPE ty_b10_path
                iv_object       TYPE xuobject
                it_values       TYPE ty_b10_fieldvals OPTIONAL
      RETURNING VALUE(rs_check) TYPE ty_b10_check.

    CLASS-METHODS decide
      IMPORTING iv_action          TYPE string
                it_checks          TYPE ty_b10_checks
      RETURNING VALUE(rs_decision) TYPE ty_b10_decision.

    CLASS-METHODS check_table
      IMPORTING iv_table_name      TYPE tabname
      RETURNING VALUE(rs_decision) TYPE ty_b10_decision.

    CLASS-METHODS check_program
      IMPORTING iv_program         TYPE programm
                iv_tcode           TYPE tcode
      RETURNING VALUE(rs_decision) TYPE ty_b10_decision.

    CLASS-METHODS check_source
      IMPORTING iv_program         TYPE programm
      RETURNING VALUE(rs_decision) TYPE ty_b10_decision.

    " Contract 3: message variables are CHAR50, so a reason travels as
    " up to four 50-character pieces of MESSAGE e001(00).
    CLASS-METHODS to_msgv
      IMPORTING iv_text TYPE string
      EXPORTING ev_v1   TYPE symsgv
                ev_v2   TYPE symsgv
                ev_v3   TYPE symsgv
                ev_v4   TYPE symsgv.
ENDCLASS.

CLASS lcl_b10_auth IMPLEMENTATION.

  METHOD rules.
    CONSTANTS lc_run    TYPE string VALUE 'report run (by name or transaction), when the program has an authorization group'.
    CONSTANTS lc_source TYPE string VALUE 'every program and include whose source is read'.

    rt_rules = VALUE #(
      " What VIEW_AUTHORITY_CHECK with action 'S' checks.
      ( path         = c_path_table
        object       = c_s_tabu_nam
        field        = 'ACTVT'
        fixed_value  = '03'
        applies_when = 'every table read'
        purpose      = 'Display authorization for the named table. Either S_TABU_NAM or S_TABU_DIS must grant it.' )
      ( path         = c_path_table
        object       = c_s_tabu_nam
        field        = 'TABLE'
        value_hint   = 'each table name read, never a wildcard'
        applies_when = 'every table read'
        purpose      = 'Names the exact tables the technical user may read.' )
      ( path         = c_path_table
        object       = c_s_tabu_dis
        field        = 'ACTVT'
        fixed_value  = '03'
        applies_when = 'table read, when S_TABU_NAM does not grant the table'
        purpose      = 'Authorization-group route to table display, the alternative to S_TABU_NAM.' )
      ( path         = c_path_table
        object       = c_s_tabu_dis
        field        = 'DICBERCLS'
        value_hint   = 'the table''s TDDAT authorization group (&NC& when it has none)'
        applies_when = 'table read, when S_TABU_NAM does not grant the table'
        purpose      = 'Authorization group that owns the table.' )
      " What SA38 requires to run a program by name.
      ( path         = c_path_by_name
        object       = c_s_tcode
        field        = 'TCD'
        fixed_value  = 'SA38'
        applies_when = 'report run by program name'
        purpose      = 'SAP runs a program by name through transaction SA38, so it requires S_TCODE SA38.' )
      " What starting a transaction requires.
      ( path         = c_path_by_tcode
        object       = c_s_tcode
        field        = 'TCD'
        value_hint   = 'the transaction code the report is started from'
        applies_when = 'report run started from a transaction code'
        purpose      = 'Authorization to start that transaction.' )
      ( path         = c_path_by_tcode
        object       = c_tstca
        field        = '*'
        value_hint   = 'the authorization object, fields and values SE93 maintains for the transaction (table TSTCA)'
        applies_when = 'report run started from a transaction code that has an authorization object in SE93'
        purpose      = 'SAP checks this object when the transaction starts; the gate calls AUTHORITY_CHECK_TCODE, which checks it with S_TCODE.' )
      ( path         = c_path_run
        object       = c_s_program
        field        = 'P_GROUP'
        value_hint   = 'the program''s authorization group (TRDIR-SECU)'
        applies_when = lc_run
        purpose      = 'Authorization to run programs in that group.' )
      ( path         = c_path_run
        object       = c_s_program
        field        = 'P_ACTION'
        fixed_value  = 'SUBMIT'
        applies_when = lc_run
        purpose      = 'Authorization to SUBMIT programs in that group.' )
      " What SE38 display requires (RS_ACCESS_PERMISSION).
      ( path           = c_path_source
        object         = c_s_develop
        field          = 'DEVCLASS'
        dummy_if_blank = abap_true
        value_hint     = 'the package in TADIR of the owning object (R3TR FUGR, CLAS, INTF, ENHO or PROG); not checked when there is none'
        applies_when   = lc_source
        purpose        = 'Package of the repository object that owns the source.' )
      ( path           = c_path_source
        object         = c_s_develop
        field          = 'OBJTYPE'
        value_hint     = 'FUGR for a function pool SAPL<group> or a function-group include L<group>...; CLAS, INTF or ENHO for class, interface or enhancement code (C, I or E at position 31 of the include name); PROG for every other program or include'
        applies_when   = lc_source
        purpose        = 'Object type SAP checks for source display: the owning repository object type.' )
      ( path           = c_path_source
        object         = c_s_develop
        field          = 'OBJNAME'
        value_hint     = 'the function group name with namespace for FUGR; the class, interface or enhancement name for CLAS, INTF or ENHO; otherwise the program or include name'
        applies_when   = lc_source
        purpose        = 'Names the programs, includes and function groups whose source may be read.' )
      ( path           = c_path_source
        object         = c_s_develop
        field          = 'P_GROUP'
        dummy_if_blank = abap_true
        value_hint     = 'TRDIR-SECU of the program or include read; not checked when it is blank, nor for class or interface code'
        applies_when   = lc_source
        purpose        = 'Authorization group of the program or include whose source is read.' )
      ( path         = c_path_source
        object       = c_s_develop
        field        = 'ACTVT'
        fixed_value  = '03'
        applies_when = lc_source
        purpose      = 'Display only. A source read never needs change authorization.' ) ).
  ENDMETHOD.

  " One codec row per rule: OBJECT|FIELD|VALUE|APPLIES_WHEN|PURPOSE, VALUE
  " being the fixed value or, for caller-supplied fields, a hint.
  METHOD rules_wire.
    DATA lv_value TYPE string.
    DATA lv_row   TYPE string.
    LOOP AT it_rules INTO DATA(ls_rule).
      IF ls_rule-fixed_value IS INITIAL.
        lv_value = ls_rule-value_hint.
      ELSE.
        lv_value = ls_rule-fixed_value.
      ENDIF.
      lv_row = lcl_plaidcl_codec=>encode_row( VALUE #( ( |{ ls_rule-object }| )
                                                       ( |{ ls_rule-field }| )
                                                       ( lv_value )
                                                       ( ls_rule-applies_when )
                                                       ( ls_rule-purpose ) ) ).
      APPEND lv_row TO rt_rows.
    ENDLOOP.
  ENDMETHOD.

  METHOD check.
    DATA lv_n     TYPE i.
    DATA lv_used  TYPE i.
    DATA lv_val   TYPE ty_b10_authval.
    DATA lv_label TYPE string.
    DATA lv_id1   TYPE xufield.
    DATA lv_id2   TYPE xufield.
    DATA lv_id3   TYPE xufield.
    DATA lv_id4   TYPE xufield.
    DATA lv_id5   TYPE xufield.
    DATA lv_val1  TYPE ty_b10_authval.
    DATA lv_val2  TYPE ty_b10_authval.
    DATA lv_val3  TYPE ty_b10_authval.
    DATA lv_val4  TYPE ty_b10_authval.
    DATA lv_val5  TYPE ty_b10_authval.

    rs_check-rc    = c_undeclared.
    rs_check-label = |{ iv_object }: object or caller values not declared for path { iv_path }|.

    DATA(lt_rules) = rules( ).
    LOOP AT lt_rules INTO DATA(ls_rule) WHERE path = iv_path AND object = iv_object.
      IF ls_rule-fixed_value IS INITIAL.
        READ TABLE it_values INTO DATA(ls_value) WITH KEY field = ls_rule-field.
        IF sy-subrc <> 0.
          RETURN.
        ENDIF.
        lv_val  = ls_value-value.
        lv_used = lv_used + 1.
      ELSE.
        lv_val = ls_rule-fixed_value.
      ENDIF.
      " SAP's own check passes such a field as DUMMY; leaving it out is the same.
      IF ls_rule-dummy_if_blank = abap_true AND lv_val IS INITIAL.
        CONTINUE.
      ENDIF.
      lv_n = lv_n + 1.
      lv_label = |{ lv_label } { ls_rule-field }={ lv_val }|.
      CASE lv_n.
        WHEN 1.
          lv_id1 = ls_rule-field.
          lv_val1 = lv_val.
        WHEN 2.
          lv_id2 = ls_rule-field.
          lv_val2 = lv_val.
        WHEN 3.
          lv_id3 = ls_rule-field.
          lv_val3 = lv_val.
        WHEN 4.
          lv_id4 = ls_rule-field.
          lv_val4 = lv_val.
        WHEN 5.
          lv_id5 = ls_rule-field.
          lv_val5 = lv_val.
        WHEN OTHERS.
          RETURN.
      ENDCASE.
    ENDLOOP.
    " A caller value the path does not declare (or a duplicate) refuses too.
    IF lv_n = 0 OR lv_used <> lines( it_values ).
      RETURN.
    ENDIF.

    rs_check-label = |{ iv_object }{ lv_label }|.
    CASE lv_n.
      WHEN 1.
        AUTHORITY-CHECK OBJECT iv_object
          ID lv_id1 FIELD lv_val1.
        rs_check-rc = sy-subrc.
      WHEN 2.
        AUTHORITY-CHECK OBJECT iv_object
          ID lv_id1 FIELD lv_val1
          ID lv_id2 FIELD lv_val2.
        rs_check-rc = sy-subrc.
      WHEN 3.
        AUTHORITY-CHECK OBJECT iv_object
          ID lv_id1 FIELD lv_val1
          ID lv_id2 FIELD lv_val2
          ID lv_id3 FIELD lv_val3.
        rs_check-rc = sy-subrc.
      WHEN 4.
        AUTHORITY-CHECK OBJECT iv_object
          ID lv_id1 FIELD lv_val1
          ID lv_id2 FIELD lv_val2
          ID lv_id3 FIELD lv_val3
          ID lv_id4 FIELD lv_val4.
        rs_check-rc = sy-subrc.
      WHEN 5.
        AUTHORITY-CHECK OBJECT iv_object
          ID lv_id1 FIELD lv_val1
          ID lv_id2 FIELD lv_val2
          ID lv_id3 FIELD lv_val3
          ID lv_id4 FIELD lv_val4
          ID lv_id5 FIELD lv_val5.
        rs_check-rc = sy-subrc.
    ENDCASE.
  ENDMETHOD.

  METHOD decide.
    DATA lt_failed TYPE string_table.

    LOOP AT it_checks INTO DATA(ls_check).
      APPEND |{ ls_check-label } rc={ ls_check-rc }| TO rs_decision-checks.
      IF ls_check-rc <> 0.
        APPEND |{ ls_check-label } rc={ ls_check-rc }| TO lt_failed.
      ENDIF.
    ENDLOOP.
    IF it_checks IS INITIAL.
      APPEND `an authorization check, but none ran` TO lt_failed.
    ENDIF.

    IF lt_failed IS INITIAL.
      rs_decision-outcome = c_granted.
      RETURN.
    ENDIF.
    rs_decision-outcome = c_denied.
    rs_decision-reason  = |{ iv_action } needs { concat_lines_of( table = lt_failed sep = `; ` ) }|.
  ENDMETHOD.

  METHOD check_table.
    SELECT SINGLE @abap_true FROM dd02l
      WHERE tabname = @iv_table_name
        AND as4local = 'A'
        AND as4vers = '0000'
      INTO @DATA(lv_exists).
    IF sy-subrc <> 0.
      rs_decision-outcome = c_not_found.
      rs_decision-reason  = |Table { iv_table_name } does not exist (no active DD02L entry)|.
      RETURN.
    ENDIF.

    CALL FUNCTION 'VIEW_AUTHORITY_CHECK'
      EXPORTING
        view_action                    = 'S'
        view_name                      = iv_table_name
      EXCEPTIONS
        invalid_action                 = 1
        no_authority                   = 2
        no_clientindependent_authority = 3
        no_linedependent_authority     = 4
        OTHERS                         = 5.
    DATA(lv_subrc) = sy-subrc.
    IF lv_subrc = 0.
      rs_decision-outcome = c_granted.
      RETURN.
    ENDIF.

    rs_decision-outcome = c_denied.
    rs_decision-reason  = |Display { iv_table_name }: VIEW_AUTHORITY_CHECK rc={ lv_subrc }; needs | &&
                          |S_TABU_NAM ACTVT=03 TABLE={ iv_table_name } or S_TABU_DIS ACTVT=03 for its authorization group|.
  ENDMETHOD.

  METHOD check_program.
    " TSTC-CINFO bits (IF_TRAN_WBI_P=>GC_CINFO, LSEUKTOP hex_*): X'80' report
    " transaction, X'10' report start variant, X'02' parameter/variant/OO
    " model transaction, X'08' OO, X'01' area menu, X'20' locked. X'04'
    " (SE93 authorization object) is AUTHORITY_CHECK_TCODE's business.
    CONSTANTS lc_kind_mask TYPE tstc-cinfo VALUE 'BB'.
    CONSTANTS lc_report    TYPE tstc-cinfo VALUE '80'.
    CONSTANTS lc_variant   TYPE tstc-cinfo VALUE '10'.
    CONSTANTS lc_param     TYPE tstc-cinfo VALUE '02'.
    CONSTANTS lc_locked    TYPE tstc-cinfo VALUE '20'.

    DATA lv_secu    TYPE trdir-secu.
    DATA lv_pgmna   TYPE tstc-pgmna.
    DATA lv_cinfo   TYPE tstc-cinfo.
    DATA lv_kind    TYPE tstc-cinfo.
    DATA lv_refusal TYPE string.
    DATA lv_action  TYPE string.
    DATA ls_check   TYPE ty_b10_check.
    DATA lt_checks  TYPE ty_b10_checks.

    SELECT SINGLE secu FROM trdir
      WHERE name = @iv_program
      INTO @lv_secu.
    IF sy-subrc <> 0.
      rs_decision-outcome = c_not_found.
      rs_decision-reason  = |Program { iv_program } does not exist (no TRDIR entry)|.
      RETURN.
    ENDIF.

    IF iv_tcode IS INITIAL.
      lv_action = |Run { iv_program } by name|.
      ls_check = check( iv_path = c_path_by_name iv_object = c_s_tcode ).
      APPEND ls_check TO lt_checks.
    ELSE.
      lv_action = |Run { iv_program } by transaction { iv_tcode }|.
      " Only a report transaction is started by SUBMIT of TSTC-PGMNA with the
      " caller's selections. A start variant or fixed parameters would make
      " caller selections looser than SAP, and a dialog, OO, menu or locked
      " transaction never SUBMITs its program at all.
      SELECT SINGLE pgmna, cinfo FROM tstc
        WHERE tcode = @iv_tcode
        INTO (@lv_pgmna, @lv_cinfo).
      IF sy-subrc <> 0.
        lv_refusal = |transaction { iv_tcode } does not exist|.
      ELSEIF lv_pgmna <> iv_program.
        lv_refusal = |transaction { iv_tcode } does not start program { iv_program }|.
      ELSE.
        lv_kind = lv_cinfo BIT-AND lc_kind_mask.
        IF lv_cinfo O lc_locked.
          lv_refusal = |transaction { iv_tcode } is locked|.
        ELSEIF lv_cinfo O lc_variant.
          lv_refusal = |report transaction { iv_tcode } defines a start variant; SAP runs it only with that variant|.
        ELSEIF lv_cinfo O lc_param.
          lv_refusal = |transaction { iv_tcode } is a parameter or variant transaction with fixed start values|.
        ELSEIF lv_kind <> lc_report.
          lv_refusal = |transaction { iv_tcode } is not a report transaction; SAP does not start it by SUBMIT of { iv_program }|.
        ELSE.
          SELECT SINGLE @abap_true FROM tstcp
            WHERE tcode = @iv_tcode
            INTO @DATA(lv_has_param).
          IF sy-subrc = 0.
            lv_refusal = |transaction { iv_tcode } defines start parameters (TSTCP)|.
          ENDIF.
        ENDIF.
      ENDIF.
      IF lv_refusal IS NOT INITIAL.
        rs_decision-outcome = c_denied.
        rs_decision-reason  = |{ lv_action }: { lv_refusal }|.
        RETURN.
      ENDIF.

      ls_check = check( iv_path   = c_path_by_tcode
                        iv_object = c_s_tcode
                        it_values = VALUE #( ( field = 'TCD' value = iv_tcode ) ) ).
      APPEND ls_check TO lt_checks.

      CALL FUNCTION 'AUTHORITY_CHECK_TCODE'
        EXPORTING
          tcode  = iv_tcode
        EXCEPTIONS
          ok     = 0
          not_ok = 2
          OTHERS = 3.
      ls_check-rc = sy-subrc.
      ls_check-label = |TSTCA authorization object of { iv_tcode } via AUTHORITY_CHECK_TCODE|.
      APPEND ls_check TO lt_checks.
    ENDIF.

    IF lv_secu IS NOT INITIAL.
      ls_check = check( iv_path   = c_path_run
                        iv_object = c_s_program
                        it_values = VALUE #( ( field = 'P_GROUP' value = lv_secu ) ) ).
      APPEND ls_check TO lt_checks.
    ENDIF.

    rs_decision = decide( iv_action = lv_action it_checks = lt_checks ).
  ENDMETHOD.

  METHOD check_source.
    DATA lv_secu      TYPE trdir-secu.
    DATA lv_progname  TYPE rs38l-include.
    DATA lv_namespace TYPE rs38l-namespace.
    DATA lv_group     TYPE rs38l-area.
    DATA lv_is_pool   TYPE c LENGTH 1.
    DATA lv_is_incl   TYPE c LENGTH 1.
    DATA lv_objtype   TYPE trobjtype.
    DATA lv_objname   TYPE sobj_name.
    DATA lv_devclass  TYPE tadir-devclass.
    DATA lv_marker    TYPE c LENGTH 1.
    DATA lv_pgroup    TYPE trdir-secu.
    DATA ls_check     TYPE ty_b10_check.
    DATA lt_checks    TYPE ty_b10_checks.

    " P_GROUP is the SECU of the program or include itself, as SAP's
    " authority_prepare reads it (LSEUQF02).
    SELECT SINGLE secu FROM trdir
      WHERE name = @iv_program
      INTO @lv_secu.
    IF sy-subrc <> 0.
      rs_decision-outcome = c_not_found.
      rs_decision-reason  = |Program { iv_program } does not exist (no TRDIR entry)|.
      RETURN.
    ENDIF.

    " SAP checks the repository object that owns the code. TR_CHECK_TYPE
    " (trint_repo_type, LSTRDF09) reads position 31 of an include name first:
    " C = class, I = interface, E = enhancement implementation, named by the
    " first 30 characters without '='. It refuses class and interface
    " includes as programs; that code is displayed as CLAS/INTF, and
    " authority_prepare (LSEUQF02) checks those kinds without P_GROUP.
    lv_pgroup = lv_secu.
    IF strlen( iv_program ) > 30.
      lv_marker  = substring( val = iv_program off = 30 len = 1 ).
      lv_objname = substring( val = iv_program len = 30 ).
      TRANSLATE lv_objname USING '= '.
      CASE lv_marker.
        WHEN 'C'.
          lv_objtype = 'CLAS'.
          CLEAR lv_pgroup.
        WHEN 'I'.
          lv_objtype = 'INTF'.
          CLEAR lv_pgroup.
        WHEN 'E'.
          lv_objtype = 'ENHO'.
      ENDCASE.
      IF lv_objtype IS NOT INITIAL.
        SELECT SINGLE devclass FROM tadir
          WHERE pgmid    = 'R3TR'
            AND object   = @lv_objtype
            AND obj_name = @lv_objname
          INTO @lv_devclass.
        IF sy-subrc <> 0.
          CLEAR lv_objtype.
          lv_pgroup = lv_secu.
        ENDIF.
      ENDIF.
    ENDIF.

    " A function pool or function-group include is R3TR FUGR
    " <namespace><group> (determine_lock_key, LSEUQF01); everything else is
    " R3TR PROG. A name SAP cannot split stays PROG there too.
    IF lv_objtype IS INITIAL.
      lv_progname = iv_program.
      CALL FUNCTION 'RS_PROGNAME_SPLIT'
        EXPORTING
          progname_with_namespace   = lv_progname
        IMPORTING
          namespace                 = lv_namespace
          fugr_is_functionpool_name = lv_is_pool
          fugr_is_include_name      = lv_is_incl
          fugr_group                = lv_group
        EXCEPTIONS
          delimiter_error           = 1
          OTHERS                    = 2.
      IF sy-subrc = 0 AND ( lv_is_pool = 'X' OR lv_is_incl = 'X' ).
        lv_objtype = 'FUGR'.
        lv_objname = |{ lv_namespace }{ lv_group }|.
      ELSE.
        lv_objtype = 'PROG'.
        lv_objname = iv_program.
      ENDIF.

      SELECT SINGLE devclass FROM tadir
        WHERE pgmid    = 'R3TR'
          AND object   = @lv_objtype
          AND obj_name = @lv_objname
        INTO @lv_devclass.
    ENDIF.

    ls_check = check( iv_path   = c_path_source
                      iv_object = c_s_develop
                      it_values = VALUE #( ( field = 'DEVCLASS' value = lv_devclass )
                                           ( field = 'OBJTYPE'  value = lv_objtype )
                                           ( field = 'OBJNAME'  value = lv_objname )
                                           ( field = 'P_GROUP'  value = lv_pgroup ) ) ).
    APPEND ls_check TO lt_checks.

    rs_decision = decide( iv_action = |Read source of { iv_program }| it_checks = lt_checks ).
  ENDMETHOD.

  METHOD to_msgv.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = iv_text
                                   IMPORTING ev_v1 = ev_v1 ev_v2 = ev_v2 ev_v3 = ev_v3 ev_v4 = ev_v4 ).
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Unit tests that need lcl_b10_auth itself, so they live in the group.
*& Run: ADT abapunit testruns against /sap/bc/adt/functions/groups/z_plaidcl.
*& They run as the current user; none asserts a live denial. The live
*& denial proof is Z_PLAIDCL_B10_DENY_VERIFY.
*&---------------------------------------------------------------------*
CLASS ltcl_b10_auth DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS table_rules_are_display_check FOR TESTING.
    METHODS wire_rows_are_codec_rows      FOR TESTING.
    METHODS msgv_splits_in_fifties        FOR TESTING.
    METHODS check_refuses_off_declaration FOR TESTING.
    METHODS no_grant_without_a_check      FOR TESTING.
    METHODS source_check_is_s_develop     FOR TESTING.
    METHODS oo_code_checks_owning_object  FOR TESTING.
    METHODS report_tcode_is_submitted     FOR TESTING.
    METHODS non_report_tcode_refused      FOR TESTING.
    METHODS declared_objects_are_checked  FOR TESTING.
ENDCLASS.

CLASS ltcl_b10_auth IMPLEMENTATION.

  METHOD table_rules_are_display_check.
    DATA lt_pairs TYPE string_table.

    DATA(lt_rules) = lcl_b10_auth=>rules( ).
    LOOP AT lt_rules INTO DATA(ls_rule) WHERE path = lcl_b10_auth=>c_path_table.
      APPEND |{ ls_rule-object }.{ ls_rule-field }={ ls_rule-fixed_value }| TO lt_pairs.
    ENDLOOP.

    cl_abap_unit_assert=>assert_equals(
      act = lt_pairs
      exp = VALUE string_table( ( `S_TABU_NAM.ACTVT=03` ) ( `S_TABU_NAM.TABLE=` )
                                ( `S_TABU_DIS.ACTVT=03` ) ( `S_TABU_DIS.DICBERCLS=` ) )
      msg = 'table rules must declare exactly SAP''s display check: S_TABU_NAM or S_TABU_DIS, ACTVT 03' ).
  ENDMETHOD.

  METHOD wire_rows_are_codec_rows.
    " Free text with the delimiter, a backslash and a line feed must survive.
    DATA(lv_text) = `line` && cl_abap_char_utilities=>newline && `feed`.
    DATA(lt_rows) = lcl_b10_auth=>rules_wire(
      VALUE #( ( path = lcl_b10_auth=>c_path_run object = 'S_PROGRAM' field = 'P_GROUP'
                 value_hint = `a|b` applies_when = `back\slash` purpose = lv_text ) ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_plaidcl_codec=>decode_row( lt_rows[ 1 ] )
      exp = VALUE string_table( ( `S_PROGRAM` ) ( `P_GROUP` ) ( `a|b` ) ( `back\slash` ) ( |{ lv_text }| ) )
      msg = |rule text must round-trip through the codec: [{ lt_rows[ 1 ] }]| ).

    lt_rows = lcl_b10_auth=>rules_wire( lcl_b10_auth=>rules( ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lines( lt_rows ) exp = lines( lcl_b10_auth=>rules( ) )
      msg = 'one wire row per rule' ).
    LOOP AT lt_rows INTO DATA(lv_row).
      DATA(lt_fields) = lcl_plaidcl_codec=>decode_row( lv_row ).
      cl_abap_unit_assert=>assert_equals(
        act = lines( lt_fields ) exp = 5
        msg = |row must decode to exactly 5 fields: [{ lv_row }]| ).
    ENDLOOP.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_plaidcl_codec=>decode_row( lt_rows[ 1 ] )
      exp = VALUE string_table( ( `S_TABU_NAM` ) ( `ACTVT` ) ( `03` )
                                ( `every table read` )
                                ( `Display authorization for the named table. Either S_TABU_NAM or S_TABU_DIS must grant it.` ) )
      msg = 'the fixed value must be on the wire in the VALUE field' ).
  ENDMETHOD.

  METHOD msgv_splits_in_fifties.
    DATA lv_v1 TYPE symsgv.
    DATA lv_v2 TYPE symsgv.
    DATA lv_v3 TYPE symsgv.
    DATA lv_v4 TYPE symsgv.

    DATA(lv_text) = repeat( val = `abcdefghij` occ = 23 ).
    lcl_b10_auth=>to_msgv( EXPORTING iv_text = lv_text
                           IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).

    cl_abap_unit_assert=>assert_equals(
      act = |{ lv_v1 }{ lv_v2 }{ lv_v3 }{ lv_v4 }|
      exp = substring( val = lv_text off = 0 len = 200 )
      msg = 'four 50-character pieces must reassemble the first 200 characters' ).
  ENDMETHOD.

  METHOD check_refuses_off_declaration.
    " None of these reaches AUTHORITY-CHECK.
    DATA(ls_check) = lcl_b10_auth=>check( iv_path = lcl_b10_auth=>c_path_run iv_object = 'S_DEVELOP' ).
    cl_abap_unit_assert=>assert_equals( act = ls_check-rc exp = lcl_b10_auth=>c_undeclared
      msg = 'an object the path does not declare must be refused' ).

    ls_check = lcl_b10_auth=>check( iv_path   = lcl_b10_auth=>c_path_source
                                    iv_object = lcl_b10_auth=>c_s_develop
                                    it_values = VALUE #( ( field = 'OBJNAME' value = 'RSPARAM' ) ) ).
    cl_abap_unit_assert=>assert_equals( act = ls_check-rc exp = lcl_b10_auth=>c_undeclared
      msg = 'a missing caller-supplied field must be refused' ).

    " SA38 is fixed for run-by-name; a caller cannot substitute a tcode it holds.
    ls_check = lcl_b10_auth=>check( iv_path   = lcl_b10_auth=>c_path_by_name
                                    iv_object = lcl_b10_auth=>c_s_tcode
                                    it_values = VALUE #( ( field = 'TCD' value = 'SE16' ) ) ).
    cl_abap_unit_assert=>assert_equals( act = ls_check-rc exp = lcl_b10_auth=>c_undeclared
      msg = 'a caller value for a fixed or undeclared field must be refused' ).
  ENDMETHOD.

  METHOD no_grant_without_a_check.
    DATA lt_checks  TYPE ty_b10_checks.
    DATA lv_program TYPE programm.

    DATA(ls_decision) = lcl_b10_auth=>decide( iv_action = `x` it_checks = lt_checks ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_denied
      msg = 'no check run must deny' ).

    lt_checks = VALUE #( ( label = `A` rc = 0 ) ).
    ls_decision = lcl_b10_auth=>decide( iv_action = `x` it_checks = lt_checks ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_granted
      msg = 'one passing check grants' ).

    lt_checks = VALUE #( ( label = `A` rc = 0 ) ( label = `B` rc = 12 ) ).
    ls_decision = lcl_b10_auth=>decide( iv_action = `x` it_checks = lt_checks ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_denied
      msg = 'any failing check denies' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-reason exp = '*B rc=12*'
      msg = |reason must name the failing check: [{ ls_decision-reason }]| ).

    " Every check_program input shape runs at least one check. Run by name
    " without a group is the shape that used to run none.
    SELECT SINGLE name FROM trdir WHERE secu = @space AND subc = '1' INTO @lv_program.
    ls_decision = lcl_b10_auth=>check_program( iv_program = lv_program iv_tcode = space ).
    cl_abap_unit_assert=>assert_equals( act = lines( ls_decision-checks ) exp = 1
      msg = |{ lv_program } by name, no group: exactly S_TCODE SA38 must run| ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ] exp = 'S_TCODE TCD=SA38 rc=*'
      msg = |{ lv_program } by name: [{ ls_decision-checks[ 1 ] }]| ).

    SELECT SINGLE name FROM trdir WHERE secu <> @space AND subc = '1' INTO @lv_program.
    ls_decision = lcl_b10_auth=>check_program( iv_program = lv_program iv_tcode = space ).
    cl_abap_unit_assert=>assert_equals( act = lines( ls_decision-checks ) exp = 2
      msg = |{ lv_program } by name, grouped: S_TCODE SA38 and S_PROGRAM must run| ).
  ENDMETHOD.

  METHOD report_tcode_is_submitted.
    " ST22 is a plain report transaction for RSSHOWRABAX (TSTC-CINFO X'80',
    " no TSTCP row, no TRDIR-SECU): S_TCODE and AUTHORITY_CHECK_TCODE run.
    DATA(ls_decision) = lcl_b10_auth=>check_program( iv_program = 'RSSHOWRABAX' iv_tcode = 'ST22' ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_granted
      msg = |ST22 starts RSSHOWRABAX by SUBMIT, so it must run: [{ ls_decision-reason }]| ).
    cl_abap_unit_assert=>assert_equals( act = lines( ls_decision-checks ) exp = 2
      msg = 'by transaction: S_TCODE and AUTHORITY_CHECK_TCODE must run' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ] exp = 'S_TCODE TCD=ST22 rc=*'
      msg = |first check: [{ ls_decision-checks[ 1 ] }]| ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 2 ] exp = '*AUTHORITY_CHECK_TCODE rc=*'
      msg = |second check: [{ ls_decision-checks[ 2 ] }]| ).
  ENDMETHOD.

  METHOD non_report_tcode_refused.
    " Each is refused before any authorization check, so DEVELOPER's
    " authorizations cannot grant it.
    " SA38: dialog transaction (CINFO X'00') of module pool SAPMS38M.
    DATA(ls_decision) = lcl_b10_auth=>check_program( iv_program = 'SAPMS38M' iv_tcode = 'SA38' ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_denied
      msg = 'a dialog transaction must be refused' ).
    cl_abap_unit_assert=>assert_initial( act = ls_decision-checks
      msg = 'a dialog transaction must be refused before any check' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-reason exp = '*SA38 is not a report transaction*'
      msg = |reason: [{ ls_decision-reason }]| ).

    " RDDPRCHK_AUDIT: report transaction with start variant SAP&_AUDIT_ALL (CINFO X'90').
    ls_decision = lcl_b10_auth=>check_program( iv_program = 'RDDPRCHK' iv_tcode = 'RDDPRCHK_AUDIT' ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_denied
      msg = 'a report transaction with a start variant must be refused' ).
    cl_abap_unit_assert=>assert_initial( act = ls_decision-checks
      msg = 'a start-variant transaction must be refused before any check' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-reason exp = '*RDDPRCHK_AUDIT defines a start variant*'
      msg = |reason: [{ ls_decision-reason }]| ).

    " SYMN: parameter transaction over SAPMSNUM (CINFO X'02', TSTCP /NSNUM ...).
    ls_decision = lcl_b10_auth=>check_program( iv_program = 'SAPMSNUM' iv_tcode = 'SYMN' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-reason exp = '*SYMN is a parameter or variant transaction*'
      msg = |a parameter transaction must be refused: [{ ls_decision-reason }]| ).

    ls_decision = lcl_b10_auth=>check_program( iv_program = 'SAPMS38M' iv_tcode = 'ST22' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-reason exp = '*ST22 does not start program SAPMS38M'
      msg = |a transaction must not run another program: [{ ls_decision-reason }]| ).
  ENDMETHOD.

  METHOD source_check_is_s_develop.
    " Function-group code is checked as SAP checks it: FUGR <group>, and a
    " blank TRDIR-SECU is not checked at all.
    DATA(ls_decision) = lcl_b10_auth=>check_source( 'LZ_PLAIDCLTOP' ).
    cl_abap_unit_assert=>assert_equals( act = lines( ls_decision-checks ) exp = 1
      msg = 'a source read runs exactly one check' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP *OBJTYPE=FUGR OBJNAME=Z_PLAIDCL *ACTVT=03 rc=*'
      msg = |a function-group include must check FUGR Z_PLAIDCL: [{ ls_decision-checks[ 1 ] }]| ).
    cl_abap_unit_assert=>assert_char_np( act = ls_decision-checks[ 1 ] exp = '*P_GROUP=*'
      msg = |a blank TRDIR-SECU must not be checked: [{ ls_decision-checks[ 1 ] }]| ).

    ls_decision = lcl_b10_auth=>check_source( 'SAPLZ_PLAIDCL' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP *OBJTYPE=FUGR OBJNAME=Z_PLAIDCL *ACTVT=03 rc=*'
      msg = |a function pool must check FUGR Z_PLAIDCL: [{ ls_decision-checks[ 1 ] }]| ).

    ls_decision = lcl_b10_auth=>check_source( 'RSPARAM' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP *OBJTYPE=PROG OBJNAME=RSPARAM *ACTVT=03 rc=*'
      msg = |a report must check PROG and its own name: [{ ls_decision-checks[ 1 ] }]| ).

    ls_decision = lcl_b10_auth=>check_source( 'Z_PLAIDCL_NO_SUCH_PROGRAM' ).
    cl_abap_unit_assert=>assert_equals( act = ls_decision-outcome exp = lcl_b10_auth=>c_not_found
      msg = 'a missing program must be NOT_FOUND' ).
  ENDMETHOD.

  METHOD oo_code_checks_owning_object.
    " Class and interface includes are checked as SAP displays them: the
    " owning CLAS/INTF with its package and no P_GROUP. An enhancement
    " include is its ENHO. A gate that checked PROG <include> fails all four.
    DATA(ls_decision) = lcl_b10_auth=>check_source( 'CL_ABAP_TYPEDESCR=============CP' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP DEVCLASS=SABP_RTTI OBJTYPE=CLAS OBJNAME=CL_ABAP_TYPEDESCR ACTVT=03 rc=*'
      msg = |a class pool must check CLAS CL_ABAP_TYPEDESCR: [{ ls_decision-checks[ 1 ] }]| ).

    ls_decision = lcl_b10_auth=>check_source( 'CL_ABAP_TYPEDESCR=============CU' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP DEVCLASS=SABP_RTTI OBJTYPE=CLAS OBJNAME=CL_ABAP_TYPEDESCR ACTVT=03 rc=*'
      msg = |a class section include must check CLAS CL_ABAP_TYPEDESCR: [{ ls_decision-checks[ 1 ] }]| ).

    ls_decision = lcl_b10_auth=>check_source( 'IF_TRAN_WBI_P=================IP' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP DEVCLASS=STRAN_DT OBJTYPE=INTF OBJNAME=IF_TRAN_WBI_P ACTVT=03 rc=*'
      msg = |an interface pool must check INTF IF_TRAN_WBI_P: [{ ls_decision-checks[ 1 ] }]| ).

    ls_decision = lcl_b10_auth=>check_source( 'DTS_BADI_CCMS_NOTIFY==========E' ).
    cl_abap_unit_assert=>assert_char_cp( act = ls_decision-checks[ 1 ]
      exp = 'S_DEVELOP DEVCLASS=SCSM OBJTYPE=ENHO OBJNAME=DTS_BADI_CCMS_NOTIFY *ACTVT=03 rc=*'
      msg = |an enhancement include must check ENHO DTS_BADI_CCMS_NOTIFY: [{ ls_decision-checks[ 1 ] }]| ).
  ENDMETHOD.

  METHOD declared_objects_are_checked.
    " Every declared path/object is one the gates check, and fits check()'s
    " five IDs. TSTCA is checked by AUTHORITY_CHECK_TCODE, TABLE rules by
    " VIEW_AUTHORITY_CHECK.
    DATA lt_pairs TYPE string_table.
    DATA lv_count TYPE i.

    DATA(lt_rules) = lcl_b10_auth=>rules( ).
    LOOP AT lt_rules INTO DATA(ls_rule).
      APPEND |{ ls_rule-path }.{ ls_rule-object }| TO lt_pairs.
    ENDLOOP.
    SORT lt_pairs.
    DELETE ADJACENT DUPLICATES FROM lt_pairs.
    cl_abap_unit_assert=>assert_equals(
      act = lt_pairs
      exp = VALUE string_table( ( `BY_NAME.S_TCODE` ) ( `BY_TCODE.S_TCODE` ) ( `BY_TCODE.TSTCA` )
                                ( `RUN.S_PROGRAM` ) ( `SOURCE.S_DEVELOP` )
                                ( `TABLE.S_TABU_DIS` ) ( `TABLE.S_TABU_NAM` ) )
      msg = 'declared path/object pairs must be exactly the ones the gates check' ).

    DATA(lt_all) = lt_rules.
    LOOP AT lt_rules INTO ls_rule WHERE path <> lcl_b10_auth=>c_path_table AND object <> lcl_b10_auth=>c_tstca.
      CLEAR lv_count.
      LOOP AT lt_all TRANSPORTING NO FIELDS WHERE path = ls_rule-path AND object = ls_rule-object.
        lv_count = lv_count + 1.
      ENDLOOP.
      cl_abap_unit_assert=>assert_number_between( lower = 1 upper = 5 number = lv_count
        msg = |{ ls_rule-path }.{ ls_rule-object }: { lv_count } fields, check() supports 1 to 5| ).
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Remote-enabled. Returns the declaration (rules_wire) as codec rows
*& OBJECT|FIELD|VALUE|APPLIES_WHEN|PURPOSE, VALUE being the fixed value
*& or, for caller-supplied fields, a hint.
*&
*& Optional preflight: IV_TABLE_NAME, IV_PROGRAM (+ IV_TCODE) and/or
*& IV_SOURCE_PROGRAM run the gate FMs for the CALLING user first and
*& raise their exception if refused. This is the only RFC route into the
*& gate FMs, which are not remote-enabled; Z_PLAIDCL_B10_DENY_VERIFY uses
*& it to prove real denials for a restricted user.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b10_authorization.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TABLE_NAME) TYPE  TABNAME OPTIONAL
*"     VALUE(IV_PROGRAM) TYPE  PROGRAMM OPTIONAL
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_SOURCE_PROGRAM) TYPE  PROGRAMM OPTIONAL
*"  EXPORTING
*"     VALUE(EV_DELIMITER) TYPE  STRING
*"     VALUE(EV_ROW_COUNT) TYPE  I
*"     VALUE(ET_DECLARED_AUTH) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      NOT_AUTHORIZED
*"      TABLE_NOT_FOUND
*"      PROGRAM_NOT_FOUND
*"----------------------------------------------------------------------



  CLEAR: ev_delimiter, ev_row_count, et_declared_auth.

  IF iv_table_name IS NOT INITIAL.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_TABLE'
      EXPORTING
        iv_table_name   = iv_table_name
      EXCEPTIONS
        not_authorized  = 1
        table_not_found = 2
        OTHERS          = 3.
    CASE sy-subrc.
      WHEN 0.
      WHEN 2.
        MESSAGE e001(00) WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 RAISING table_not_found.
      WHEN OTHERS.
        MESSAGE e001(00) WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 RAISING not_authorized.
    ENDCASE.
  ENDIF.

  IF iv_program IS NOT INITIAL.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
      EXPORTING
        iv_program        = iv_program
        iv_tcode          = iv_tcode
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
    CASE sy-subrc.
      WHEN 0.
      WHEN 2.
        MESSAGE e001(00) WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 RAISING program_not_found.
      WHEN OTHERS.
        MESSAGE e001(00) WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 RAISING not_authorized.
    ENDCASE.
  ENDIF.

  IF iv_source_program IS NOT INITIAL.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_SOURCE'
      EXPORTING
        iv_program        = iv_source_program
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
    CASE sy-subrc.
      WHEN 0.
      WHEN 2.
        MESSAGE e001(00) WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 RAISING program_not_found.
      WHEN OTHERS.
        MESSAGE e001(00) WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 RAISING not_authorized.
    ENDCASE.
  ENDIF.

  ev_delimiter     = lcl_b10_auth=>c_delimiter.
  et_declared_auth = lcl_b10_auth=>rules_wire( lcl_b10_auth=>rules( ) ).
  ev_row_count     = lines( et_declared_auth ).

ENDFUNCTION.
