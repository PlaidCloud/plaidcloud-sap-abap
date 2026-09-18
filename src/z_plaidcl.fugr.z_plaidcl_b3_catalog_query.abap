*&---------------------------------------------------------------------*
*& sc-27791 (B3 -- Z_PLAIDCL_B3_CATALOG_QUERY, RFC wrapper).
*&---------------------------------------------------------------------*
* Thin, remote-enabled FM wrapper around the AUnit-verified logic in
* z_plaidcl_b3_catalog_query.abap (REPORT, UNMODIFIED, still live). That
* REPORT's LCL_QUERY_CATALOG=>ENUMERATE_AREA / RESOLVE_QUERY /
* COUNT_OUTPUT_LISTS are copied here near-verbatim (renamed under a b3
* prefix for group-scope hygiene; RESOLVE_QUERY's own TY_QUERY_ENTRY
* WORKSPACE field is dropped -- the caller already knows which
* workspace it asked for, see TY_B3_ENTRY below) so an FM body can call
* them and flatten a catalog page onto the wire.
*
* IMPORTANT (same note the REPORT itself carries): RSAQ_REMOTE_QUERY_
* CATALOG is NOT itself RFC-enabled despite its name. It IS reachable
* as a normal internal ABAP call from a program that is itself invoked
* over RFC -- which is exactly this FM's own calling shape (the same
* architecture B1/sc-27787 already proved live).
*
* Deploys into the SAME Z_PLAIDCL function group as B1/B2/B5/B6/B7/B8/
* B12. New names introduced here: LCL_B3_QUERY_CATALOG (class),
* TY_B3_ENTRY (type, body-scope-only use).
*
* IV_WORKSPACE is 'STANDARD'/'GLOBAL' (string), not a bare space/'G'
* char -- same reasoning as B6's own IV_WORKSPACE: an inline TYPE c
* LENGTH n in a signature is a known activation trap, and STRING both
* sidesteps it and is a clearer API. The FM body maps it to the single
* char RSAQ_REMOTE_QUERY_CATALOG/RSAQ_REPORT_NAME actually want.
*
* IV_RESOLVE controls cost, not correctness: with IV_RESOLVE=abap_false
* (the default) this FM only enumerates the catalog page (workspace/
* usergroup/queryname/title) -- cheap, no source read at all. With
* IV_RESOLVE=abap_true it ALSO resolves each entry's deterministic
* report name (RSAQ_REPORT_NAME -- a pure name computation, never a
* generation call) and, ONLY when that report ALREADY exists in TRDIR,
* reads its field list and a best-effort output-list count. THIS FM
* NEVER CALLS RSAQ_GENERATE_PROGRAM (S3): an SQ01 catalog browse must
* never generate or regenerate a customer's report as a side effect --
* that is a repository write with no read-only equivalent, and the
* pre-fix code did it unconditionally, on every resolve, even for a
* program that already existed. A query whose report was never opened/
* generated in SQ01 or SA38 simply has no field list or output-list
* count available from this call; STRUCT carries a status token
* instead (see WIRE CONTRACT). Per the REPORT's own header: output-list
* count is best-effort metadata -- it gates slicing, not availability,
* same status as B4's own additivity metadata; NEVER treat
* OUTPUT_LIST_CNT=-1 as "zero lists". Both FIELD_CNT and OUTPUT_LIST_CNT
* default to -1 for every early-return path (NAME_RESOLUTION_FAILED,
* NOT_GENERATED, NOT_AUTHORIZED, SOURCE_UNREADABLE) where the count was
* never even attempted -- a pre-merge review finding: OUTPUT_LIST_CNT
* previously stayed a fabricated 0 on those paths. STRUCT_NOT_FOUND is
* NOT an early return: the output-list scan still runs against the full
* expanded source regardless of whether STRUCT resolved, so it reports
* its real count there, while FIELD_CNT stays -1 (there is no structure
* to look fields up for). FIELD_CNT is likewise -1, not 0, when its own
* DD03L lookup fails after STRUCT resolved successfully -- never confuse
* an unreadable field list with a genuinely empty one. FIELD_CNT is ALSO
* -1 (R3 finding 2) when the DD03L read hits its own RFC_READ_TABLE
* ROWCOUNT=200 page size: that is a "structure has at least 200 fields,
* real count unknown" signal, not a real count, and this FM never
* reports a truncated number as exact. The DD03L read itself filters to
* the active version (AS4LOCAL='A', AS4VERS='0000') and excludes
* .INCLUDE/.APPEND marker rows (FIELDNAME NOT LIKE '.%'), the same DD03L
* filter B5 applies (z_plaidcl_b5_read_table.abap) -- a pre-merge review
* finding: an inactive/revised duplicate row or an unexcluded marker row
* could otherwise inflate FIELD_CNT, or push it past 200 into a
* fabricated -1 for a structure that is not actually that wide.
*
* Any read of a resolved program's source goes through B7's shared
* LCL_B7_TCODE_CAPTURE=>READ_SOURCE (z_plaidcl_b7_run_tcode.abap, the
* same engine B4/B13 already use), which expands INCLUDEs transitively
* and runs Z_PLAIDCL_B10_CHECK_SOURCE (S_DEVELOP display, Contract 1
* extension) on the main program AND every include BEFORE reading it.
* R4: a generated SQ01 report always declares its extract structure
* (`TABLES <struct>.`) in the query generator's OWN declaration include,
* named "...DAT" by the /1BCDWB/ generator convention -- e.g. Q_DR_V_01
* -> TABLES /SAPQUERY/TA00 in /1BCDWB/IQG000000000001DAT. Reading only
* the main program (the pre-fix code's plain READ REPORT) therefore
* reported STRUCT_NOT_FOUND on EVERY generated query; STRUCT is now
* resolved from the *DAT include specifically (a pre-merge review
* finding: taking the first TABLES statement anywhere in the whole
* expanded source risked picking an unrelated one -- an InfoSet's join
* tables, or main-program boilerplate like `TABLES: SSCRFIELDS.`).
* A denial anywhere in the include chain is reported per-entry as
* STRUCT="NOT_AUTHORIZED" rather than failing the whole catalog call:
* this FM's existing design
* already reports per-entry outcomes (a query catalog page mixes many
* independently-owned queries), so a refusal on one entry follows that
* same shape instead of aborting entries the caller IS authorized to see.
*
* WIRE CONTRACT:
*   - ET_ENTRIES rows are CODEC rows (lcl_plaidcl_codec=>encode_row /
*     decode_row, Contract 2), exactly 8 fields in this fixed order:
*       "WORKSPACE|USERGROUP|QUERYNAME|REPORTNAME|STRUCT|FIELD_CNT|
*        OUTPUT_LIST_CNT|TITLE"
*     TITLE is free-form, user-authored query description text
*     (RSAQRQCAT-QTEXT) and can contain a pipe or a backslash. A caller
*     MUST decode with the codec, never a plain `split('|')`: the codec
*     escapes every field, so decoding always recovers exactly 8 fields
*     regardless of what TITLE contains.
*   - REPORTNAME is populated once IV_RESOLVE=abap_true (it is a pure
*     name computation, not dependent on generation) EXCEPT on the
*     NAME_RESOLUTION_FAILED path below, where RSAQ_REPORT_NAME itself
*     failed and REPORTNAME stays blank alongside STRUCT (CT3: there is
*     no name to report there). STRUCT is either the real structure name
*     (resolved from source, gated) or one of these status tokens, in
*     place of blank, when resolution stopped short: NOT_GENERATED
*     (TRDIR has no such program yet), NOT_AUTHORIZED
*     (Z_PLAIDCL_B10_CHECK_SOURCE refused), SOURCE_UNREADABLE (READ
*     REPORT failed after the gate passed), STRUCT_NOT_FOUND (source
*     read but no `TABLES <struct>.` found in a *DAT include), or
*     NAME_RESOLUTION_FAILED (RSAQ_REPORT_NAME itself failed, REPORTNAME
*     blank too). FIELD_CNT is -1 (R4: unknown, never a fabricated 0 --
*     a field count is only ever real once STRUCT genuinely resolves) in
*     every status-token case. OUTPUT_LIST_CNT is likewise -1 for
*     NAME_RESOLUTION_FAILED/NOT_GENERATED/NOT_AUTHORIZED/
*     SOURCE_UNREADABLE (the source was never read, or refused), but a
*     REAL count for STRUCT_NOT_FOUND -- the output-list scan runs
*     against the full expanded source independently of STRUCT
*     resolution, so it genuinely completed there.
*     REPORTNAME/STRUCT/FIELD_CNT/OUTPUT_LIST_CNT are blank/0 (not a
*     status token, and both counts are 0 here specifically, not -1)
*     when IV_RESOLVE=abap_false was passed -- no resolution was
*     attempted at all, which is a different, honest "not asked" state.
*   - SN3: a catalog row is included only when the caller holds S_QUERY
*     ACTVT 23 ("superuser", member of every group -- SAPMS38R FORM
*     GET_USER_GROUP) or is assigned to the row's own user group in the
*     requested area (AQLDB cluster for STANDARD, AQGDBBN for GLOBAL --
*     read via RSAQ_IMPORT_USERGROUP_CATALOG's O_DBBN, the same source
*     B6's worker reads). RSAQ_REMOTE_QUERY_CATALOG itself does not
*     filter by membership -- same gap SN3 found in RSAQ_QUERY_CALL.
*   - DB2 / R3 finding 1: when RSAQ_REMOTE_QUERY_CATALOG itself fails, OR
*     (for a non-superuser) the SQ01 membership catalog itself cannot be
*     read, this FM raises CATALOG_UNAVAILABLE (Contract 3) instead of a
*     silent empty/filtered success -- neither an empty catalog nor "no
*     rows matched membership" may ever be indistinguishable from "the
*     read failed".
*   - EV_TRUNCATED is real ABAP_BOOL ('X' / single space) -- compare
*     explicitly, same caveat as every other Bn FM in this package.
*
* SCOPE: target is SAP_BASIS 816 ABAP Platform, no S4CORE -- there are
* no ERP business queries to enumerate here, only Basis-layer SQ01
* queries live on this trial system.
*&---------------------------------------------------------------------*

" ABAP forbids inline type construction (TYPE STANDARD TABLE OF x) in a
" METHODS signature -- same class of restriction as TYPE c LENGTH n
" (proven live landing B7's own ty_b7_seltab). Named type, referenced
" below, not inlined into ENUMERATE_AREA's own RETURNING clause.
TYPES ty_b3_catalog TYPE STANDARD TABLE OF rsaqrqcat WITH DEFAULT KEY.
TYPES ty_b3_rfc_db_opt_tab TYPE STANDARD TABLE OF rfc_db_opt WITH DEFAULT KEY.

TYPES: BEGIN OF ty_b3_entry,
         usergroup      TYPE string,
         queryname      TYPE string,
         title          TYPE string,
         reportname     TYPE string,
         struct         TYPE string,
         field_cnt      TYPE i,
         output_list_cnt TYPE i,
       END OF ty_b3_entry.

CLASS lcl_b3_query_catalog DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_delimiter TYPE c LENGTH 1 VALUE '|'.
    " Contract 5: every caller-supplied row limit is capped at 50000,
    " refused (never silently clamped) above it.
    CONSTANTS c_max_entries_cap TYPE i VALUE 50000.

    " Verbatim copy of z_plaidcl_b3_catalog_query.abap's own
    " LCL_QUERY_CATALOG=>ENUMERATE_AREA, plus EV_FAILED (DB2): a classic-
    " EXCEPTIONS FM cannot be RAISEd from inside a local class method, so
    " a genuine RSAQ_REMOTE_QUERY_CATALOG failure is reported back as a
    " flag and RAISED at FM level by the caller (Contract 3).
    CLASS-METHODS enumerate_area
      IMPORTING pv_workspace       TYPE c
      EXPORTING ev_failed          TYPE abap_bool
      RETURNING VALUE(rt_catalog)  TYPE ty_b3_catalog.

    " SN3: true only when the caller may see every user group's queries
    " without a membership check -- S_QUERY ACTVT 23 (SAPMS38R "Superuser
    " sind in jeder Benutzergruppe").
    CLASS-METHODS is_superuser
      RETURNING VALUE(rv_yes) TYPE abap_bool.

    " SN3: the set of user groups (NUM, uppercased) SY-UNAME is assigned
    " to in the given area, fetched ONCE per call rather than once per
    " catalog row. EV_FAILED means the membership catalog itself could
    " not be read -- fail closed (treat as member of nothing), never as
    " superuser. Mirrors B6's own worker approach (z_plaidcl_b6_run_query.
    " abap LCL_B6_QUERY=>MEMBERSHIP_DENIAL) as a fresh copy: B6's method
    " is local-class-private and not visible here.
    CLASS-METHODS my_usergroups
      IMPORTING pv_workspace     TYPE c
      EXPORTING ev_failed        TYPE abap_bool
      RETURNING VALUE(rt_groups) TYPE string_table.

    " S3: no longer generates. Resolves the deterministic report name
    " (RSAQ_REPORT_NAME), and reads the field list/output-list count
    " ONLY when TRDIR already has that program -- see file header for
    " the full status-token contract when it does not, or when the
    " gated source read is refused or fails.
    CLASS-METHODS resolve_query
      IMPORTING pv_workspace      TYPE c
                ps_cat            TYPE rsaqrqcat
      RETURNING VALUE(rs_entry)   TYPE ty_b3_entry.

    " S3, extracted so the "never generate" branch decision is
    " unit-testable without a live query in either state (R3/R4 review:
    " on this trial Q_DR_V_01 is already generated, so a live test only
    " ever exercises PV_PROGRAM_EXISTS=abap_true -- the false branch,
    " and the polarity of this decision, would otherwise go unpinned).
    CLASS-METHODS is_not_generated
      IMPORTING pv_program_exists       TYPE abap_bool
      RETURNING VALUE(rv_not_generated) TYPE abap_bool.

    " R3 finding 2 / R4, extracted so the whole FIELD_CNT decision is
    " unit-testable without a live 200+-field DDIC structure or a live
    " unresolved-STRUCT query. PV_STRUCT_RESOLVED=abap_false means STRUCT
    " never resolved to a real name at all (NAME_RESOLUTION_FAILED,
    " NOT_GENERATED, NOT_AUTHORIZED, SOURCE_UNREADABLE, STRUCT_NOT_FOUND)
    " -- there is no field list to look up, so -1 (unknown), never a
    " fabricated 0 (R4). Otherwise PV_SUBRC/PV_ROWS_READ are exactly
    " RFC_READ_TABLE's own SY-SUBRC and LINES( DATA ) against DD03L with
    " ROWCOUNT=200: -1 on a read failure (never "zero fields") AND on
    " hitting the page exactly (never report a truncated count as real).
    CLASS-METHODS decide_field_cnt
      IMPORTING pv_struct_resolved TYPE abap_bool
                pv_subrc           TYPE sy-subrc DEFAULT 0
                pv_rows_read       TYPE i        DEFAULT 0
      RETURNING VALUE(rv_field_cnt) TYPE i.

    " Best-effort: count distinct list-level markers in an ALREADY-READ
    " source table (never reads source itself -- resolve_query does the
    " one gated READ REPORT and passes its result in here, so a program
    " is never read from source twice).
    CLASS-METHODS count_output_lists_from_source
      IMPORTING it_source           TYPE string_table
      RETURNING VALUE(rv_list_cnt)  TYPE i.

    " R4 pre-merge blocker: the extract structure is declared in the
    " query generator's OWN declaration include, named "...DAT" by the
    " /1BCDWB/ generator convention (confirmed live for Q_DR_V_01:
    " /1BCDWB/IQG000000000001DAT) -- the SAME include naming SAP's own
    " generator always uses, not a per-query accident. An InfoSet's other
    " includes can carry unrelated TABLES statements (join tables,
    " PERFORM ... TABLES, boilerplate like SSCRFIELDS in the main
    " program); taking the first TABLES match anywhere in the whole
    " expanded source risked picking the wrong one. Takes the FULL
    " include-tagged source (TYPE ty_b7_src_lines, from B7's shared
    " READ_SOURCE) so it can restrict the search to *DAT includes.
    " Returns blank, never a guess, when no such statement is found in
    " any *DAT include -- the caller reports STRUCT_NOT_FOUND and
    " FIELD_CNT/OUTPUT_LIST_CNT stay -1, never a wrong structure.
    CLASS-METHODS extract_struct_name
      IMPORTING it_source        TYPE ty_b7_src_lines
      RETURNING VALUE(rv_struct) TYPE string.

    " R4 pre-merge blocker: mirrors B5's own DD03L filter
    " (z_plaidcl_b5_read_table.abap) -- active version (AS4LOCAL='A'),
    " version 0000 (so an inactive/revised duplicate row never inflates
    " the count), and excludes .INCLUDE/.APPEND marker rows (their real
    " fields are listed as their own DD03L rows, same as B5). RFC_READ_
    " TABLE's OPTIONS text truncates at 72 characters PER ROW, so each
    " condition is its own row with its own leading AND. Isolated from
    " the RFC_READ_TABLE call so the filter clauses are unit-testable
    " without RFC.
    CLASS-METHODS build_field_options
      IMPORTING pv_struct         TYPE string
      RETURNING VALUE(rt_options) TYPE ty_b3_rfc_db_opt_tab.

    " ORCHESTRATION. Not part of the proven REPORT (its AUnit methods
    " called ENUMERATE_AREA/RESOLVE_QUERY/COUNT_OUTPUT_LISTS directly,
    " one at a time, for a single hardcoded query) -- this is the new
    " logic this FM wrapper adds: page the catalog, optionally resolve
    " each entry, and flatten to the wire, all in one call.
    CLASS-METHODS run
      IMPORTING pv_workspace         TYPE c
                pv_usergroup_filter  TYPE string
                pv_queryname_filter  TYPE string
                pv_resolve           TYPE abap_bool
                pv_max_entries       TYPE i
      EXPORTING ev_truncated         TYPE abap_bool
                ev_catalog_failed    TYPE abap_bool
                ev_membership_failed TYPE abap_bool
                et_rows              TYPE string_table.
ENDCLASS.

CLASS lcl_b3_query_catalog IMPLEMENTATION.

  METHOD enumerate_area.
    CLEAR ev_failed.
    CALL FUNCTION 'RSAQ_REMOTE_QUERY_CATALOG'
      EXPORTING
        workspace           = pv_workspace
        generic_queryname   = '*'
        generic_usergroup   = '*'
        generic_funcarea    = '*'
        with_system_objects = 'X'
      TABLES
        querycatalog = rt_catalog
      EXCEPTIONS
        error_message = 1
        OTHERS        = 2.
    IF sy-subrc <> 0.
      " DB2: a genuine catalog-read failure is reported to the caller
      " (which RAISEs CATALOG_UNAVAILABLE at FM level), never returned as
      " an indistinguishable empty success.
      CLEAR rt_catalog.
      ev_failed = abap_true.
    ENDIF.
  ENDMETHOD.

  METHOD is_superuser.
    AUTHORITY-CHECK OBJECT 'S_QUERY' ID 'ACTVT' FIELD '23'.
    rv_yes = xsdbool( sy-subrc = 0 ).
  ENDMETHOD.

  METHOD my_usergroups.
    CLEAR: ev_failed, rt_groups.

    DATA lv_prefix TYPE aqadef-pgname.
    DATA lv_ws     TYPE aqadef-wsid.
    DATA lv_all    TYPE c LENGTH 1 VALUE 'X'.
    DATA lt_ptab   TYPE abap_func_parmbind_tab.
    DATA lt_etab   TYPE abap_func_excpbind_tab.
    DATA lr_table  TYPE REF TO data.
    DATA lr_dbbn   TYPE REF TO data.
    FIELD-SYMBOLS <lt_dbbn>   TYPE ANY TABLE.
    FIELD-SYMBOLS <ls_member> TYPE any.
    FIELD-SYMBOLS <lv_group>  TYPE any.
    FIELD-SYMBOLS <lv_user>   TYPE any.

    lv_prefix = COND #( WHEN pv_workspace = 'G' THEN 'AQZZ' ELSE 'AQ00' ).
    CALL FUNCTION 'RSAQ_DECODE_REPORT_NAME'
      EXPORTING
        reportname = lv_prefix
      IMPORTING
        workspace  = lv_ws
      EXCEPTIONS
        OTHERS     = 1.
    IF sy-subrc <> 0.
      ev_failed = abap_true.
      RETURN.
    ENDIF.

    " The TABLES parameters are bound from the FM's own interface, so no
    " catalog structure name is hard-coded here -- same reflection B6
    " uses, so a kernel change to that structure cannot silently desync.
    SELECT parameter, structure FROM fupararef
      WHERE funcname  = 'RSAQ_IMPORT_USERGROUP_CATALOG'
        AND r3state   = 'A'
        AND paramtype = 'T'
      INTO TABLE @DATA(lt_tables).
    TRY.
        LOOP AT lt_tables INTO DATA(ls_table).
          CREATE DATA lr_table TYPE TABLE OF (ls_table-structure).
          INSERT VALUE #( name = ls_table-parameter kind = abap_func_tables value = lr_table ) INTO TABLE lt_ptab.
          IF ls_table-parameter = 'O_DBBN'.
            lr_dbbn = lr_table.
          ENDIF.
        ENDLOOP.
        IF lr_dbbn IS NOT BOUND.
          ev_failed = abap_true.
          RETURN.
        ENDIF.
        INSERT VALUE #( name = 'I_WSPACE' kind = abap_func_exporting value = REF #( lv_ws ) ) INTO TABLE lt_ptab.
        INSERT VALUE #( name = 'I_ALL' kind = abap_func_exporting value = REF #( lv_all ) ) INTO TABLE lt_ptab.
        INSERT VALUE #( name = 'OTHERS' value = 1 ) INTO TABLE lt_etab.
        CALL FUNCTION 'RSAQ_IMPORT_USERGROUP_CATALOG'
          PARAMETER-TABLE lt_ptab
          EXCEPTION-TABLE lt_etab.
        IF sy-subrc <> 0.
          ev_failed = abap_true.
          RETURN.
        ENDIF.
      CATCH cx_sy_create_data_error cx_sy_dyn_call_error.
        ev_failed = abap_true.
        RETURN.
    ENDTRY.

    ASSIGN lr_dbbn->* TO <lt_dbbn>.
    LOOP AT <lt_dbbn> ASSIGNING <ls_member>.
      ASSIGN COMPONENT 'NUM' OF STRUCTURE <ls_member> TO <lv_group>.
      IF sy-subrc = 0.
        ASSIGN COMPONENT 'BNAME' OF STRUCTURE <ls_member> TO <lv_user>.
      ENDIF.
      IF sy-subrc <> 0.
        ev_failed = abap_true.
        RETURN.
      ENDIF.
      IF <lv_user> = sy-uname.
        DATA lv_group_str TYPE string.
        lv_group_str = <lv_group>.
        APPEND to_upper( lv_group_str ) TO rt_groups.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD resolve_query.
    rs_entry-usergroup = ps_cat-num.
    rs_entry-queryname = ps_cat-query.
    rs_entry-title     = ps_cat-qtext.
    " R4: default for every early-return path below (STRUCT never even
    " attempted, or explicitly refused) -- unknown, never a fabricated 0.
    " STRUCT_NOT_FOUND and the success path both fall through to the
    " real COUNT_OUTPUT_LISTS_FROM_SOURCE call below and overwrite this;
    " it is a genuine best-effort scan independent of STRUCT resolution.
    rs_entry-field_cnt       = decide_field_cnt( pv_struct_resolved = abap_false ).
    rs_entry-output_list_cnt = -1.

    DATA lv_reportname TYPE aqadef-pgname.
    CALL FUNCTION 'RSAQ_REPORT_NAME'
      EXPORTING
        workspace  = pv_workspace
        usergroup  = ps_cat-num
        query      = ps_cat-query
      IMPORTING
        reportname = lv_reportname
      EXCEPTIONS
        error_message = 1
        OTHERS        = 2.
    IF sy-subrc <> 0.
      rs_entry-struct = `NAME_RESOLUTION_FAILED`.
      RETURN.
    ENDIF.
    rs_entry-reportname = lv_reportname.

    " S3: never generate. A query whose report was never opened/saved in
    " SQ01 or SA38 simply has no field list or output-list count here.
    DATA lv_exists TYPE trdir-name.
    SELECT SINGLE name FROM trdir INTO lv_exists WHERE name = lv_reportname.
    IF is_not_generated( xsdbool( sy-subrc = 0 ) ) = abap_true.
      rs_entry-struct = `NOT_GENERATED`.
      RETURN.
    ENDIF.

    " R4 (live A4H defect): a generated SQ01 report declares its extract
    " structure in an INCLUDE, never the main program -- Q_DR_V_01's
    " TABLES /SAPQUERY/TA00 lives in /1BCDWB/IQG000000000001DAT. The
    " pre-fix code's plain READ REPORT of only the main program therefore
    " reported STRUCT_NOT_FOUND on EVERY generated query. B7's shared
    " READ_SOURCE expands includes transitively and runs the Contract 1
    " S_DEVELOP gate on each one (main program and every include, same
    " helper B4/B13 already use) -- a denial anywhere in the chain still
    " surfaces as NOT_AUTHORIZED, and a genuine read failure anywhere
    " still surfaces as SOURCE_UNREADABLE, exactly as before.
    DATA(ls_source) = lcl_b7_tcode_capture=>read_source( lv_reportname ).
    IF ls_source-denied = abap_true.
      rs_entry-struct = `NOT_AUTHORIZED`.
      RETURN.
    ENDIF.
    IF ls_source-readable = abap_false.
      rs_entry-struct = `SOURCE_UNREADABLE`.
      RETURN.
    ENDIF.

    rs_entry-struct = extract_struct_name( ls_source-src ).
    IF rs_entry-struct IS INITIAL.
      rs_entry-struct = `STRUCT_NOT_FOUND`.
    ELSE.
      DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
      DATA lt_data    TYPE STANDARD TABLE OF tab512.
      APPEND VALUE #( fieldname = 'FIELDNAME' ) TO lt_fields.
      " A classic CALL FUNCTION's TABLES parameter is bound by reference
      " and cannot take an inline functional-call result -- same class of
      " restriction as the DATA()/VALUE# shorthand ban on EXPORTING/
      " IMPORTING (proven live elsewhere in this package).
      DATA(lt_options) = build_field_options( rs_entry-struct ).
      " R3 finding 2 / R4 pre-merge blocker: ROWCOUNT=200 is a page size,
      " not a cap on the real answer -- see DECIDE_FIELD_CNT. The WHERE
      " filters (active version, non-marker rows) come from
      " BUILD_FIELD_OPTIONS, the same DD03L filter B5 applies, so an
      " inactive/revised duplicate or an .INCLUDE/.APPEND marker row can
      " never inflate this count. RFC_READ_TABLE's own authorization
      " check (S_TABU_DIS/NAM on DD03L) is a property of RFC_READ_TABLE
      " itself, not of a plain OpenSQL SELECT -- switching to
      " `SELECT COUNT(*) FROM dd03l` here would read DD03L with LESS
      " authorization checking than today, not more capability, so it's
      " not used.
      CALL FUNCTION 'RFC_READ_TABLE'
        EXPORTING query_table = 'DD03L' delimiter = '|' rowcount = 200
        TABLES options = lt_options fields = lt_fields data = lt_data
        EXCEPTIONS OTHERS = 7.
      rs_entry-field_cnt = decide_field_cnt( pv_struct_resolved = abap_true pv_subrc = sy-subrc pv_rows_read = lines( lt_data ) ).
    ENDIF.

    DATA lt_source TYPE string_table.
    LOOP AT ls_source-src INTO DATA(ls_src_line).
      APPEND ls_src_line-code TO lt_source.
    ENDLOOP.
    rs_entry-output_list_cnt = count_output_lists_from_source( lt_source ).
  ENDMETHOD.

  METHOD is_not_generated.
    rv_not_generated = xsdbool( pv_program_exists = abap_false ).
  ENDMETHOD.

  METHOD decide_field_cnt.
    IF pv_struct_resolved = abap_false.
      rv_field_cnt = -1.   " R4: no STRUCT to look fields up for -- unknown, NEVER a fabricated 0
    ELSEIF pv_subrc <> 0.
      rv_field_cnt = -1.   " DD03L read failed -- NOT "zero fields", same convention as OUTPUT_LIST_CNT
    ELSEIF pv_rows_read >= 200.
      rv_field_cnt = -1.   " capped at ROWCOUNT=200 -- unknown, NEVER report a truncated count as real
    ELSE.
      rv_field_cnt = pv_rows_read.
    ENDIF.
  ENDMETHOD.

  METHOD extract_struct_name.
    " RR2: each line is short and fixed by construction (a single ABAP
    " statement), so CX_SY_REGEX_TOO_COMPLEX is unreachable here in
    " practice -- caught anyway so a pathological line degrades to
    " STRUCT_NOT_FOUND (the caller's existing honest-negative status),
    " never an uncaught dump.
    " R4 pre-merge blocker: restricted to *DAT includes (see the class
    " definition comment for why), anchored so TABLES must be the
    " statement's own keyword at the start of the line (never a
    " substring inside another identifier, e.g. APPEND x TO
    " lt_tables_new.), and the captured name is restricted to
    " [/A-Z0-9_] so a stray quote can never ride into a later OPTIONS
    " string built from this value. The colon stays optional -- both
    " `TABLES <s>.` and `TABLES: <s>.` are real generated forms.
    LOOP AT it_source INTO DATA(ls_line) WHERE incl CP '*DAT'.
      TRY.
          FIND REGEX '^\s*TABLES:?\s+([/A-Z0-9_]+)\s*\.' IN ls_line-code IGNORING CASE SUBMATCHES rv_struct.
        CATCH cx_sy_regex_too_complex.
          CONTINUE.
      ENDTRY.
      IF sy-subrc = 0.
        rv_struct = to_upper( rv_struct ).
        RETURN.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD build_field_options.
    " Each row is concatenated verbatim by RFC_READ_TABLE with no
    " inserted separator, so every row but the last carries its own
    " trailing space before the next row's leading AND.
    APPEND VALUE #( text = |TABNAME = '{ pv_struct }' | ) TO rt_options.
    APPEND VALUE #( text = `AND AS4LOCAL = 'A' ` ) TO rt_options.
    APPEND VALUE #( text = `AND AS4VERS = '0000' ` ) TO rt_options.
    APPEND VALUE #( text = `AND FIELDNAME NOT LIKE '.%'` ) TO rt_options.
  ENDMETHOD.

  METHOD count_output_lists_from_source.
    " RR2: see extract_struct_name -- a too-complex line is skipped
    " (undercounts by that one line) rather than dumping the whole scan;
    " OUTPUT_LIST_CNT is already documented best-effort metadata.
    LOOP AT it_source INTO DATA(lv_line).
      TRY.
          FIND REGEX 'FORM\s+LIST\d*\s*\.' IN lv_line IGNORING CASE.
        CATCH cx_sy_regex_too_complex.
          CONTINUE.
      ENDTRY.
      IF sy-subrc = 0.
        rv_list_cnt = rv_list_cnt + 1.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD run.
    CLEAR: ev_catalog_failed, ev_membership_failed.
    DATA(lt_cat) = enumerate_area( EXPORTING pv_workspace = pv_workspace IMPORTING ev_failed = ev_catalog_failed ).
    IF ev_catalog_failed = abap_true.
      RETURN.
    ENDIF.

    " SN3: fetched once for the whole call, not once per catalog row.
    DATA(lv_superuser) = is_superuser( ).
    DATA lt_my_groups TYPE string_table.
    IF lv_superuser = abap_false.
      lt_my_groups = my_usergroups( EXPORTING pv_workspace = pv_workspace IMPORTING ev_failed = ev_membership_failed ).
      IF ev_membership_failed = abap_true.
        " R3 finding 1: a caller who cannot be proven a member of anything
        " is NOT the same as a caller who is a member of nothing -- an
        " unreadable membership catalog must not silently degrade into an
        " empty (or worse, all-rows-hidden) success. Same DB2-class fix:
        " abort the whole call, never a partial/empty result.
        RETURN.
      ENDIF.
    ENDIF.

    DATA(lv_ws_label) = COND string( WHEN pv_workspace = 'G' THEN 'GLOBAL' ELSE 'STANDARD' ).

    " DN-b: EV_TRUNCATED reflects only what the caller actually receives
    " after every filter (usergroup/queryname/SN3 membership), never the
    " raw unfiltered catalog size.
    DATA(lv_seen) = 0.
    LOOP AT lt_cat INTO DATA(ls_cat).
      IF pv_usergroup_filter <> '*' AND to_upper( ls_cat-num ) <> to_upper( pv_usergroup_filter ).
        CONTINUE.
      ENDIF.
      IF pv_queryname_filter <> '*' AND to_upper( ls_cat-query ) <> to_upper( pv_queryname_filter ).
        CONTINUE.
      ENDIF.
      IF lv_superuser = abap_false AND NOT line_exists( lt_my_groups[ table_line = to_upper( ls_cat-num ) ] ).
        CONTINUE.
      ENDIF.

      lv_seen = lv_seen + 1.
      IF lv_seen > pv_max_entries.
        ev_truncated = abap_true.
        EXIT.
      ENDIF.

      DATA(lv_reportname) = ``.
      DATA(lv_struct)     = ``.
      DATA(lv_field_cnt)  = 0.
      DATA(lv_list_cnt)   = 0.
      DATA(lv_title)      = ls_cat-qtext.

      IF pv_resolve = abap_true.
        DATA(ls_entry) = resolve_query( pv_workspace = pv_workspace ps_cat = ls_cat ).
        lv_reportname = ls_entry-reportname.
        lv_struct     = ls_entry-struct.
        lv_field_cnt  = ls_entry-field_cnt.
        lv_list_cnt   = ls_entry-output_list_cnt.
        lv_title      = ls_entry-title.
      ENDIF.

      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ lv_ws_label }| )
        ( |{ ls_cat-num }| )
        ( |{ ls_cat-query }| )
        ( |{ lv_reportname }| )
        ( |{ lv_struct }| )
        ( |{ lv_field_cnt }| )
        ( |{ lv_list_cnt }| )
        ( |{ lv_title }| ) ) ) TO et_rows.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& THE FUNCTION MODULE ITSELF.
*&
*& Remote-enabled (RFC). Deploys as Z_PLAIDCL_B3_CATALOG_QUERY inside
*& the live Z_PLAIDCL function group. Signature is INLINE between the
*& FUNCTION name and the terminating period -- see z_plaidcl_ping.abap.
*&---------------------------------------------------------------------*
FUNCTION Z_PLAIDCL_B3_CATALOG_QUERY.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_WORKSPACE) TYPE  STRING DEFAULT 'STANDARD'
*"     VALUE(IV_USERGROUP_FILTER) TYPE  STRING DEFAULT '*'
*"     VALUE(IV_QUERYNAME_FILTER) TYPE  STRING DEFAULT '*'
*"     VALUE(IV_RESOLVE) TYPE  BOOLE_D DEFAULT ' '
*"     VALUE(IV_MAX_ENTRIES) TYPE  I DEFAULT 500
*"  EXPORTING
*"     VALUE(EV_DELIMITER) TYPE  STRING
*"     VALUE(EV_ENTRY_COUNT) TYPE  I
*"     VALUE(EV_TRUNCATED) TYPE  BOOLE_D
*"     VALUE(ET_ENTRIES) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      CATALOG_UNAVAILABLE
*"----------------------------------------------------------------------



  DATA lv_catalog_failed    TYPE abap_bool.
  DATA lv_membership_failed TYPE abap_bool.
  DATA lv_v1 TYPE symsgv.
  DATA lv_v2 TYPE symsgv.
  DATA lv_v3 TYPE symsgv.
  DATA lv_v4 TYPE symsgv.

  CLEAR: ev_delimiter, ev_entry_count, ev_truncated, et_entries.

  DATA lv_ws_char TYPE c LENGTH 1.
  IF to_upper( iv_workspace ) = 'GLOBAL'.
    lv_ws_char = 'G'.
  ELSEIF to_upper( iv_workspace ) = 'STANDARD' OR iv_workspace IS INITIAL.
    lv_ws_char = space.
  ELSE.
    MESSAGE e001(00) WITH 'IV_WORKSPACE must be GLOBAL or STANDARD' RAISING invalid_input.
  ENDIF.

  IF iv_max_entries < 1 OR iv_max_entries > lcl_b3_query_catalog=>c_max_entries_cap.
    MESSAGE e001(00) WITH 'IV_MAX_ENTRIES must be between 1 and 50000' RAISING invalid_input.
  ENDIF.

  ev_delimiter = lcl_b3_query_catalog=>c_delimiter.

  lcl_b3_query_catalog=>run(
    EXPORTING pv_workspace         = lv_ws_char
              pv_usergroup_filter  = iv_usergroup_filter
              pv_queryname_filter  = iv_queryname_filter
              pv_resolve           = iv_resolve
              pv_max_entries       = iv_max_entries
    IMPORTING ev_truncated         = ev_truncated
              ev_catalog_failed    = lv_catalog_failed
              ev_membership_failed = lv_membership_failed
              et_rows              = et_entries ).

  " DB2: RSAQ_REMOTE_QUERY_CATALOG itself failed -- report it, never an
  " empty success indistinguishable from "no queries". msg_chunks re-flows
  " one continuous sentence across the 4 chunks so a caller concatenating
  " SY-MSGV1..4 gets real word breaks, never "catalogdata"/"therequested".
  IF lv_catalog_failed = abap_true.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = `RSAQ_REMOTE_QUERY_CATALOG failed; catalog data is unavailable, not empty, for the requested workspace.`
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING catalog_unavailable.
  ENDIF.

  " R3 finding 1: the SQ01 user-group membership catalog itself could not
  " be read for a non-superuser -- never a silent empty/filtered success.
  IF lv_membership_failed = abap_true.
    lcl_plaidcl_stage=>msg_chunks(
      EXPORTING iv_text = `SQ01 user-group membership catalog (RSAQ_IMPORT_USERGROUP_CATALOG) could not be read; results would be unreliable.`
      IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING catalog_unavailable.
  ENDIF.

  ev_entry_count = lines( et_entries ).

ENDFUNCTION.

*&---------------------------------------------------------------------*
*& D2 codec regression: TITLE is free-form RSAQRQCAT-QTEXT and can
*& itself contain a pipe or backslash. The pre-fix code built ET_ENTRIES
*& with a raw pipe join, which would over-split on exactly this input;
*& the codec must not. Local class logic only -- no RFC, no repository
*& write, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b3fm_codec DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS title_pipe_backslash_roundtrip FOR TESTING.
ENDCLASS.

CLASS ltcl_b3fm_codec IMPLEMENTATION.
  METHOD title_pipe_backslash_roundtrip.
    DATA(lv_title) = `Sales | Region report, path C:\reports\q1`.

    DATA(lv_row) = lcl_plaidcl_codec=>encode_row( VALUE string_table(
      ( `STANDARD` )
      ( `/SAPQUERY/BC` )
      ( `Q_TEST` )
      ( `NOT_GENERATED` )
      ( `NOT_GENERATED` )
      ( `0` )
      ( `0` )
      ( |{ lv_title }| ) ) ).
    DATA(lt_decoded) = lcl_plaidcl_codec=>decode_row( lv_row ).

    cl_abap_unit_assert=>assert_equals( act = lines( lt_decoded ) exp = 8
      msg = |field count must stay 8 despite embedded \| and \\ in TITLE: [{ lv_row }]| ).
    cl_abap_unit_assert=>assert_equals( act = lt_decoded[ 8 ] exp = lv_title
      msg = |TITLE must round-trip exactly, pipe and backslash included: [{ lv_row }]| ).
    cl_abap_unit_assert=>assert_equals( act = lt_decoded[ 2 ] exp = `/SAPQUERY/BC`
      msg = |USERGROUP must not have absorbed part of TITLE: [{ lv_row }]| ).
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& S3 regression, pinned at the unit level: on THIS trial Q_DR_V_01 is
*& already generated, so a live test (r_b3_resolve_status_truth in
*& z_plaidcl_verify_b1b4.abap) only ever exercises PV_PROGRAM_EXISTS=
*& abap_true. This pins the polarity of the "never generate" decision
*& itself in both states, so it stays caught even while the false branch
*& is unreachable live. It does NOT prove RESOLVE_QUERY still calls this
*& method instead of falling through to a generate call -- that half is
*& only provable live, by r_b3_resolve_status_truth's own S3 assertion,
*& once (or if) an ungenerated query becomes available on this trial.
*& Local class logic only -- no RFC, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b3fm_not_generated DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS missing_prog_not_generated FOR TESTING.
    METHODS existing_prog_is_generated FOR TESTING.
ENDCLASS.

CLASS ltcl_b3fm_not_generated IMPLEMENTATION.
  METHOD missing_prog_not_generated.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>is_not_generated( abap_false )
      exp = abap_true
      msg = 'a program absent from TRDIR must classify NOT_GENERATED' ).
  ENDMETHOD.

  METHOD existing_prog_is_generated.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>is_not_generated( abap_true )
      exp = abap_false
      msg = 'a program present in TRDIR must NOT classify NOT_GENERATED' ).
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& Pre-merge blocker regression: EXTRACT_STRUCT_NAME pinned directly
*& over a synthetic multi-include source -- no live query needed.
*& Reverting the line anchor (APPEND ... TO lt_tables_new. matching
*& again), the *DAT restriction (a non-DAT include's TABLES statement
*& winning), or the captured-character restriction all fail one of
*& these. Local class logic only -- no RFC, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b3fm_struct_name DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS append_to_tables_var_no_match FOR TESTING.
    METHODS plain_tables_in_dat_include FOR TESTING.
    METHODS chained_tables_in_dat_include FOR TESTING.
    METHODS ignores_tables_outside_dat FOR TESTING.
ENDCLASS.

CLASS ltcl_b3fm_struct_name IMPLEMENTATION.
  METHOD append_to_tables_var_no_match.
    " Coordinator's own example: a variable NAMED lt_tables_new must
    " never be misread as a TABLES statement target.
    DATA(lt_src) = VALUE ty_b7_src_lines(
      ( incl = '/1BCDWB/IQG000000000001DAT' line = 1 code = `APPEND x TO lt_tables_new.` ) ).
    cl_abap_unit_assert=>assert_initial(
      act = lcl_b3_query_catalog=>extract_struct_name( lt_src )
      msg = 'APPEND ... TO lt_tables_new. must never match as a TABLES statement' ).
  ENDMETHOD.

  METHOD plain_tables_in_dat_include.
    DATA(lt_src) = VALUE ty_b7_src_lines(
      ( incl = '/1BCDWB/IQG000000000001DAT' line = 1 code = `  TABLES /SAPQUERY/TA00.` ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>extract_struct_name( lt_src )
      exp = `/SAPQUERY/TA00`
      msg = 'leading blanks then plain TABLES <s>. must match' ).
  ENDMETHOD.

  METHOD chained_tables_in_dat_include.
    DATA(lt_src) = VALUE ty_b7_src_lines(
      ( incl = '/1BCDWB/IQG000000000001DAT' line = 1 code = `TABLES: SFLIGHT.` ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>extract_struct_name( lt_src )
      exp = `SFLIGHT`
      msg = 'chained TABLES: <s>. must still match' ).
  ENDMETHOD.

  METHOD ignores_tables_outside_dat.
    " Multi-TABLES pin: a non-DAT include's own TABLES statement (main-
    " program boilerplate, or an InfoSet join table) must be ignored even
    " though it is scanned FIRST, in favor of the real one in the *DAT
    " include that appears later.
    DATA(lt_src) = VALUE ty_b7_src_lines(
      ( incl = 'AQZZSAPQUERYBCQ_DR_V_01=====' line = 1 code = `TABLES: SSCRFIELDS.` )
      ( incl = '/1BCDWB/IQG000000000001DAT'   line = 1 code = `  TABLES /SAPQUERY/TA00.` ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>extract_struct_name( lt_src )
      exp = `/SAPQUERY/TA00`
      msg = 'a TABLES statement outside a *DAT include must never win over the real one' ).
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& Pre-merge blocker regression: BUILD_FIELD_OPTIONS pinned directly --
*& no live RFC_READ_TABLE call needed. Proves the active-version filter
*& and the .INCLUDE/.APPEND exclusion are BOTH present, and that no row
*& violates RFC_READ_TABLE's own 72-character-per-row OPTIONS limit.
*& Local class logic only -- no RFC, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b3fm_options DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS filters_active_and_markers FOR TESTING.
    METHODS rows_fit_72_char_limit FOR TESTING.
ENDCLASS.

CLASS ltcl_b3fm_options IMPLEMENTATION.
  METHOD filters_active_and_markers.
    DATA(lv_where) = concat_lines_of( table = lcl_b3_query_catalog=>build_field_options( `/SAPQUERY/TA00` ) ).
    cl_abap_unit_assert=>assert_char_cp( act = lv_where exp = `*TABNAME = '/SAPQUERY/TA00'*`
      msg = |WHERE must filter on TABNAME: [{ lv_where }]| ).
    cl_abap_unit_assert=>assert_char_cp( act = lv_where exp = `*AS4LOCAL = 'A'*`
      msg = |WHERE must filter to the active version: [{ lv_where }]| ).
    cl_abap_unit_assert=>assert_char_cp( act = lv_where exp = `*AS4VERS = '0000'*`
      msg = |WHERE must filter to version 0000: [{ lv_where }]| ).
    cl_abap_unit_assert=>assert_char_cp( act = lv_where exp = |*FIELDNAME NOT LIKE '.%'*|
      msg = |WHERE must exclude .INCLUDE/.APPEND marker rows: [{ lv_where }]| ).
  ENDMETHOD.

  METHOD rows_fit_72_char_limit.
    " A namespaced structure name near DDIC's practical maximum, so this
    " catches a future TABNAME row growing past RFC_READ_TABLE's own
    " 72-char-per-OPTIONS-row limit, not just today's short test names.
    DATA(lt_options) = lcl_b3_query_catalog=>build_field_options( `/PLAIDCLOUD_NS/A_FAIRLY_LONG_STRUCTURE_NAME` ).
    LOOP AT lt_options INTO DATA(ls_option).
      cl_abap_unit_assert=>assert_true( act = xsdbool( strlen( ls_option-text ) <= 72 )
        msg = |OPTIONS row exceeds RFC_READ_TABLE's 72-char limit: [{ ls_option-text }]| ).
    ENDLOOP.
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& R3 finding 2 / R4 regression: DECIDE_FIELD_CNT pinned directly, with
*& stubbed inputs -- no live 200+-field DDIC structure and no live
*& unresolved-STRUCT query needed. Reverting any branch of the fix
*& (e.g. back to "IF sy-subrc = 0. field_cnt = lines(...). ENDIF." with
*& no cap/failure/unresolved handling) fails one of these. Local class
*& logic only -- no RFC, genuinely HARMLESS.
*&---------------------------------------------------------------------*
CLASS ltcl_b3fm_field_cnt DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS read_failure_is_unknown FOR TESTING.
    METHODS exact_page_boundary_is_unknown FOR TESTING.
    METHODS under_page_is_real_count FOR TESTING.
    METHODS unresolved_struct_is_unknown FOR TESTING.
ENDCLASS.

CLASS ltcl_b3fm_field_cnt IMPLEMENTATION.
  METHOD read_failure_is_unknown.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>decide_field_cnt( pv_struct_resolved = abap_true pv_subrc = 7 pv_rows_read = 0 )
      exp = -1
      msg = 'a failed DD03L read must report -1 (unknown), never 0 fields' ).
  ENDMETHOD.

  METHOD exact_page_boundary_is_unknown.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>decide_field_cnt( pv_struct_resolved = abap_true pv_subrc = 0 pv_rows_read = 200 )
      exp = -1
      msg = 'hitting ROWCOUNT=200 exactly must report -1 (unknown), never the truncated 200' ).
  ENDMETHOD.

  METHOD under_page_is_real_count.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>decide_field_cnt( pv_struct_resolved = abap_true pv_subrc = 0 pv_rows_read = 47 )
      exp = 47
      msg = 'a read that stayed under the page must still report its real count' ).
  ENDMETHOD.

  METHOD unresolved_struct_is_unknown.
    " R4: NAME_RESOLUTION_FAILED / NOT_GENERATED / NOT_AUTHORIZED /
    " SOURCE_UNREADABLE / STRUCT_NOT_FOUND all route through this one
    " call with PV_STRUCT_RESOLVED=abap_false -- pinning it here catches
    " a revert to a fabricated 0 default without needing a live query in
    " any of those five states.
    cl_abap_unit_assert=>assert_equals(
      act = lcl_b3_query_catalog=>decide_field_cnt( pv_struct_resolved = abap_false )
      exp = -1
      msg = 'an unresolved STRUCT must report -1 (unknown), never a fabricated 0' ).
  ENDMETHOD.
ENDCLASS.

*&---------------------------------------------------------------------*
*& VERIFICATION CHECKLIST (mechanical pass once the system is usable).
*& NOT activated or run this session -- see z_plaidcl_b1_capabilities_
*& fm.abap's own checklist header for why. Static-only pass done,
*& nothing executed on a kernel.
*&
*& Deploy:
*&   source scripts/adt.sh; adt_init
*&   adt_deploy_fm Z_PLAIDCL Z_PLAIDCL_B3_CATALOG_QUERY \
*&     src/z_plaidcl_b3_catalog_query_fm.abap "B3 SQ01 catalog/resolve (RFC)"
*&   Confirm put=200 AND activationExecuted="true" with ZERO messages.
*&
*& 1. Call with IV_WORKSPACE='GLOBAL', IV_RESOLVE=abap_false,
*&    IV_MAX_ENTRIES=50. EXPECT: EV_ENTRY_COUNT >= 1 (this trial system
*&    ships at least the /SAPQUERY/BC query area), REPORTNAME/STRUCT/
*&    FIELD_CNT/OUTPUT_LIST_CNT blank/0 on every row (no resolve done).
*& 2. Call with IV_WORKSPACE='GLOBAL', IV_USERGROUP_FILTER=
*&    '/SAPQUERY/BC', IV_QUERYNAME_FILTER='Q_DR_V_01', IV_RESOLVE=
*&    abap_true. EXPECT: exactly one row, REPORTNAME=
*&    "AQZZ/SAPQUERY/BCQ_DR_V_01=====" (deterministic, from
*&    RSAQ_REPORT_NAME, no generation). If that report was already
*&    generated by an earlier SQ01/SA38 run on this system, STRUCT is
*&    its REAL structure name -- on this trial, /SAPQUERY/TA00 (R4:
*&    declared in include /1BCDWB/IQG000000000001DAT, not the main
*&    program) -- and FIELD_CNT is its real DD03L field count, or -1 if
*&    that count is 200 or more. If it was never generated, STRUCT =
*&    "NOT_GENERATED" and FIELD_CNT=-1 (R4: unknown, never 0) -- also a
*&    valid, honest outcome (S3): confirm TRDIR has no such program name
*&    to tell the two cases apart before asserting either.
*& 2b. Confirm S3 directly: SE16 TRDIR before and after step 2 for the
*&    resolved report name -- the row count and TIMESTAMP must be
*&    IDENTICAL. The pre-fix code would have created or re-touched it.
*& 3. Call with IV_WORKSPACE='BOGUS'. EXPECT: EXCEPTION INVALID_INPUT,
*&    no RSAQ_* call made.
*& 4. Call with IV_MAX_ENTRIES=1 against a filter known to match more
*&    than one entry (or IV_USERGROUP_FILTER/IV_QUERYNAME_FILTER left
*&    at '*' in the GLOBAL area). EXPECT: EV_TRUNCATED = 'X',
*&    EV_ENTRY_COUNT = 1 exactly.
*& 5. Group-level activation check: confirm B1/B2/B5/B6/B7/B8/B12 (GET
*&    200 on each) are unchanged after this FM lands in the same unit.
*& 6. SN3: as a user with NO S_QUERY authorization and NOT assigned to
*&    /SAPQUERY/BC (e.g. ZPLAIDRESTR), call IV_WORKSPACE='GLOBAL',
*&    IV_USERGROUP_FILTER='/SAPQUERY/BC'. EXPECT: EV_ENTRY_COUNT=0 (the
*&    row from step 2 is filtered out) -- then repeat as ZPLAIDQRY23
*&    (S_QUERY ACTVT 23) and confirm the row reappears without being a
*&    DBBN member. See z_plaidcl_verify_b1b4.abap methods P/Q.
*& 7. DB2 (CATALOG_UNAVAILABLE): NOT independently inducible from valid
*&    caller input on this trial -- RSAQ_REMOTE_QUERY_CATALOG's only
*&    documented failure paths (bad WORKSPACE) are already intercepted
*&    earlier by this FM's own IV_WORKSPACE validation (step 3), so no
*&    live input reaches the CALL FUNCTION in a failing state. Verified
*&    statically only: ENUMERATE_AREA's EXCEPTIONS clause maps
*&    ERROR_MESSAGE/OTHERS to EV_FAILED=abap_true, RUN propagates it as
*&    EV_CATALOG_FAILED and returns before building any row, and the FM
*&    body raises CATALOG_UNAVAILABLE and never reaches EV_ENTRY_COUNT
*&    on that path -- confirm by code inspection, or by temporarily
*&    renaming RSAQ_REMOTE_QUERY_CATALOG in a throwaway copy if a live
*&    negative proof is required.
*& 8. R3 finding 1 (membership catalog CATALOG_UNAVAILABLE): also NOT
*&    independently inducible from valid input on this trial, for the
*&    same reason as step 7 -- RSAQ_IMPORT_USERGROUP_CATALOG's only
*&    reachable failure paths (a missing O_DBBN table, a dynamic-call
*&    error) require a broken kernel/DDIC, not a caller-controllable
*&    input. Verified statically: MY_USERGROUPS sets EV_FAILED on every
*&    one of its three failure branches, RUN returns before the loop
*&    when EV_MEMBERSHIP_FAILED is set (never a partial/empty row set),
*&    and the FM body raises CATALOG_UNAVAILABLE on that path too.
*& 9. R3 finding 2 (FIELD_CNT page-size cap): LTCL_B3FM_FIELD_CNT pins
*&    the -1-on-cap / -1-on-failure / real-count-under-200 decision
*&    directly (no live 200+-field structure needed) and runs as part of
*&    this file's own AUnit. If a query with a genuinely wide (200+
*&    field) generated structure is later found or built on this trial
*&    (SE11 append or a wide custom InfoSet), resolving it is an
*&    additional live confirmation: EXPECT FIELD_CNT=-1, never 200. A
*&    structure under 200 fields must still report its real count
*&    (regression: confirm step 2's /SAPQUERY/BC Q_DR_V_01 still shows
*&    FIELD_CNT>0 if generated).
*& 10. R4 (STRUCT resolved through the *DAT include): live-confirmed by
*&     z_plaidcl_verify_b1b4.abap's r_b3_resolve_status_truth, which now
*&     asserts STRUCT="/SAPQUERY/TA00" exactly (not merely "some
*&     non-token value") and cross-checks FIELD_CNT against an
*&     INDEPENDENT Open SQL SELECT COUNT(*) FROM dd03l (active version,
*&     non-marker rows), not B3's own RFC_READ_TABLE call echoed back at
*&     itself. STRUCT_NOT_FOUND reappearing for Q_DR_V_01 is this test's
*&     own regression signal.
*& 11. S3 "never generate" polarity: LTCL_B3FM_NOT_GENERATED pins
*&     IS_NOT_GENERATED directly for both PV_PROGRAM_EXISTS states, so
*&     the decision stays caught even though this trial's Q_DR_V_01 is
*&     already generated and r_b3_resolve_status_truth therefore only
*&     ever live-exercises the "exists" branch. This does NOT prove
*&     RESOLVE_QUERY still calls IS_NOT_GENERATED rather than falling
*&     through to a generate call -- only a live ungenerated query (none
*&     known on this trial today) can prove that half, via
*&     r_b3_resolve_status_truth's own S3 TRDIR-unchanged assertion.
*& 12. Pre-merge blocker (DD03L filter + multi-TABLES): LTCL_B3FM_OPTIONS
*&     pins BUILD_FIELD_OPTIONS's WHERE text directly (active version,
*&     .INCLUDE/.APPEND exclusion, no row over 72 chars) and
*&     LTCL_B3FM_STRUCT_NAME pins EXTRACT_STRUCT_NAME over a synthetic
*&     multi-include source (a non-DAT include's own TABLES statement
*&     must lose to the real one in a *DAT include) -- neither needs a
*&     live RFC/kernel call. A live structure KNOWN to carry an
*&     .INCLUDE/.APPEND (e.g. SOTR_USE, found via DD03L) is an optional
*&     additional live confirmation if one is ever resolved through B3,
*&     but is not required: the builder is fully isolated and unit-
*&     tested above.
*& 13. Pre-merge blocker (OUTPUT_LIST_CNT sweep): live-confirmed by
*&     r_b3_resolve_status_truth's NOT_GENERATED branch and
*&     s_b3_resolve_not_auth_qry23 (both assert OUTPUT_LIST_CNT=-1).
*&
*& NOT verifiable on this SAP_BASIS 816, no-S4CORE trial system: only
*& Basis-layer SQ01 queries exist to enumerate here -- there are no ERP
*& business queries on this trial system, same scope note as the REPORT
*& this file wraps.
*&---------------------------------------------------------------------*
