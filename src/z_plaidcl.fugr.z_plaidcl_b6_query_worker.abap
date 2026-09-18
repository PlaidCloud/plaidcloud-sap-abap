*&---------------------------------------------------------------------*
*& sc-27798 (B6 -- Z_PLAIDCL_B6_RUN_QUERY + Z_PLAIDCL_B6_QUERY_WORKER).
*&---------------------------------------------------------------------*
* Runs an SQ01 query through SAP's own query API, RSAQ_QUERY_CALL with
* SKIP_SELSCREEN and DATA_TO_MEMORY, and returns its first output list as
* codec rows. Both FMs are remote-enabled, group Z_PLAIDCL.
*
* ISOLATION: Z_PLAIDCL_B6_RUN_QUERY calls the worker only via DESTINATION
* 'NONE' and closes that connection after every call (ABAP and SAP memory
* would otherwise persist on it). A bad selection value (E message), a
* popup, a memory overflow or a dump inside the generated query program
* ends only the loopback session; it comes back as SYSTEM_FAILURE and is
* raised as CAPTURE_ABORTED carrying SAP's text.
*
* AUTHORIZATION: the worker can be called directly over RFC, so every check
* runs inside the worker; B6 adds only the isolation. It matches what SAP
* enforces when a query runs, nothing more:
*   - SQ00/SQ01's user-group rule (SAPMS38R FORM GET_USER_GROUP):
*     - a holder of S_QUERY ACTVT 23 is a "superuser" and a member of
*       every user group;
*     - anyone else must be assigned to the query's group in the requested
*       area (a DBBN row with BNAME = SY-UNAME).
*     RSAQ_QUERY_CALL enforces neither, so the worker does. It reads the
*     assignment through SAP's own catalog FM RSAQ_IMPORT_USERGROUP_CATALOG
*     (O_DBBN, type AQDBBN), because membership lives in the AQLDB cluster
*     for the standard area and in AQGDBBN for the global area. It fails
*     closed: an unreadable catalog means NOT_AUTHORIZED.
*   - S_PROGRAM SUBMIT on the generated report: RSAQ_QUERY_CALL's own
*     SUBMIT_REPORT_AUTHORIZATION (NO_SUBMIT_AUTH -> NOT_AUTHORIZED).
*   An InfoSet with table-access authority (CL_QUERY_TAB_ACCESS_AUTHORITY)
*   refuses inside the generated program; that surfaces as
*   CAPTURE_ABORTED.
*
* BASIS DISCLOSURE: the first execution of a query generates its AQ*
* report program, and a query that changed since then is regenerated,
* through RSAQ_CREATE_QUERY_REPORT. SAP does this whenever a query runs,
* in SQ01 exactly as here. Later runs generate nothing. Generation happens
* only after the user-group check.
*
* ROW LIMIT: DBACC is SAP's database-read budget. When the budget runs out,
* the generated program STOPs silently and outputs what it has read so
* far, including statistics computed over that partial read. It is
* therefore never used as a limit:
*   - 0 (unlimited) when IT_SELECTION holds a SELECT-OPTIONS row;
*   - 1000000000 otherwise, because RSAQ_QUERY_CALL refuses a run with no
*     selection, no variant and DBACC 0. Not 2147483647: the generated
*     program then dies with an integer overflow (proven on A4H).
* IV_MAX_ROWS (at most 50000) is applied to the returned rows.
* BYTE BUDGET: the returned rows, as wire text (2 bytes per character,
* as B5 counts), stop at 32 MB. The worker stops before the row that
* would cross it. Hitting either limit sets EV_TRUNCATED.
* MEMORY: both limits apply only after the query has run. With DBACC 0
* (any SELECT-OPTIONS row) the generated program reads EVERY matching
* database row before the cap is applied. It holds that whole result in
* the worker session about twice over: once in its list table, and once
* in the copy RSAQ_QUERY_CALL imports from ABAP memory. That is bounded
* only by the work process's heap and extended-memory quota. An overflow
* dumps the loopback session alone and arrives as CAPTURE_ABORTED; the
* caller never holds more than the capped rows. Narrow the selection for
* large InfoSets.
*
* LISTS: only the first output list is returned. EV_LIST_ID is G00 for a
* basic list, Tnn for statistics, Rnn for a ranked list. A list with a
* non-elementary column is refused as QUERY_UNAVAILABLE; the ranked lists
* on A4H are like that.
*
* WIRE (lcl_plaidcl_codec rows):
*   IT_SELECTION  SELNAME|KIND|SIGN|OPTION|LOW|HIGH
*                 - SELNAME must be a field on the query's selection screen,
*                   because SAP silently ignores an unknown name and returns
*                   the full result;
*                 - '%' output controls are refused;
*                 - every OBLIGATORY field needs a value;
*                 - LOW/HIGH must be in SAP's INTERNAL format, exactly as
*                   the database stores them: dates YYYYMMDD, NUMC and
*                   ALPHA-converted keys with their leading zeros (CONNID
*                   0017, not 17). An external-format value is not
*                   converted; it selects nothing and returns 0 rows with
*                   no error.
*   ET_FIELDS     POSITION|FIELDNAME|ROLLNAME|DATATYPE|LENGTH|DECIMALS|
*                 DESCRIPTION|CURRENCY_ROLE|REF_COLUMN
*                 - FIELDNAME is the list column, and ROLLNAME its DDIC type
*                   (empty for computed fields).
*                 - DATATYPE, LENGTH, DECIMALS and DESCRIPTION come from
*                   LISTDESC (FTYP, FLEN, FDEC, FDESC).
*                 - CURRENCY_ROLE is LISTDESC-FCUR as-is: F amount,
*                   W currency key, M quantity, E unit, or ''.
*                 - REF_COLUMN, on an F or M column, is the FIELDNAME of
*                   its currency or unit column, taken from
*                   RSAQ_QUERY_CALL's FPAIRS; '' when there is none.
*                   FPAIRS names columns by list position (FLPOS) and has
*                   no list id. Pairing is proven on a single-line list
*                   only; REF_COLUMN is also '' when a position matches
*                   no column or several (a multi-line list), when the
*                   roles don't fit, or when FPAIRS gives one column two
*                   partners. '' never means "no currency", only "not
*                   known for certain".
*                 Differs from B7's ET_FIELDS (same first six names): the
*                 7th field is DESCRIPTION (the query's column text), not
*                 NOTE; DATATYPE is an ABAP type letter (LISTDESC-FTYP, or
*                 the RTTI type kind: C N D T P I F ...), not a DDIC data
*                 type name (CHAR, CURR, DATS ...); and B7 has no fields 8-9.
*   ET_ROWS       one row per list line: numbers with a leading minus;
*                 dates and times raw (YYYYMMDD, HHMMSS); NUMC with its
*                 leading zeros. CURR/QUAN values are SAP's internal
*                 amount, with the decimals of the DDIC type rather than
*                 of the currency (JPY 10.00 internal is 1000 JPY); read
*                 them with the REF_COLUMN value of the same row.
* NO_DATA_SELECTED is a normal return with zero rows that still carries
* ET_FIELDS, EV_LIST_ID and EV_COLUMN_COUNT when the generated report can
* describe its list. On that path the generated report exports only its
* "empty" flag, so RSAQ_QUERY_CALL returns no LISTDESC and no FPAIRS. The
* worker reads LISTDESC and the list's line type from the report's own
* %READ_LDESC and %GET_REF_TO_TABLE forms. There is no form for FPAIRS,
* so REF_COLUMN is '' on a zero-row result.
* EV_LIST_ID is the fixed id %READ_LDESC returns. ET_FIELDS stays empty
* when the report name can't be resolved, a form is missing, or the list
* shape is one a run with data refuses. The form interface is proven only
* on BT/D1. A generated report whose %READ_LDESC or %GET_REF_TO_TABLE
* interface differs dumps the NONE worker, so the caller gets
* CAPTURE_ABORTED on a zero-row run. Errors are MESSAGE e001(00) ...
* RAISING (Contract 3).
*&---------------------------------------------------------------------*

TYPES ty_b6_rsparams TYPE STANDARD TABLE OF rsparams WITH DEFAULT KEY.
TYPES ty_b6_spnames TYPE STANDARD TABLE OF rsaqspname WITH DEFAULT KEY.
TYPES ty_b6_ldescs TYPE STANDARD TABLE OF rsaqldesc WITH DEFAULT KEY.
TYPES ty_b6_fpairs TYPE STANDARD TABLE OF rsaqfpairs WITH DEFAULT KEY.
TYPES ty_b6_flags TYPE STANDARD TABLE OF abap_bool WITH EMPTY KEY.

TYPES: BEGIN OF ty_b6_pair,
         column TYPE string,
         ref    TYPE string,
       END OF ty_b6_pair.
TYPES ty_b6_pairs TYPE HASHED TABLE OF ty_b6_pair WITH UNIQUE KEY column.

TYPES: BEGIN OF ty_b6_result,
         error        TYPE string,
         text         TYPE string,
         list_id      TYPE string,
         column_count TYPE i,
         truncated    TYPE abap_bool,
         fields       TYPE string_table,
         rows         TYPE string_table,
       END OF ty_b6_result.

CLASS lcl_b6_query DEFINITION FINAL.
  PUBLIC SECTION.
    " RS_RESULT-ERROR is the worker's exception key, initial on success.
    CLASS-METHODS run
      IMPORTING iv_workspace     TYPE string
                iv_usergroup     TYPE string
                iv_queryname     TYPE string
                iv_max_rows      TYPE i
                it_selection     TYPE string_table
      RETURNING VALUE(rs_result) TYPE ty_b6_result.

    " Z_PLAIDCL_B6_SELSCREEN: the query's selection fields as codec rows in
    " RS_RESULT-FIELDS, after the same name and user-group checks as RUN.
    CLASS-METHODS describe_selection
      IMPORTING iv_workspace     TYPE string
                iv_usergroup     TYPE string
                iv_queryname     TYPE string
      RETURNING VALUE(rs_result) TYPE ty_b6_result.

    " One SEL_FIELDS entry as the B6_SELSCREEN codec row
    " SELNAME|KIND|OBLIGATORY|ROLLNAME|DESCRIPTION|NOTE|DATATYPE|LENGTH.
    " Public for ltcl_b6_selscreen.
    CLASS-METHODS selection_field_row
      IMPORTING is_spn        TYPE rsaqspname
      RETURNING VALUE(rv_row) TYPE string.

    " Amount/quantity column -> its currency/unit column, both named by
    " LISTDESC-FNAMEINT (the list table's component name, = ET_FIELDS
    " FIELDNAME). An RSAQFPAIRS row holds list positions, not names:
    " INDEX_A = LISTDESC-FLPOS of the amount/quantity column, INDEX_U = FLPOS
    " of its currency/unit column. Proven on A4H BT/D1: FPAIRS 0006/0007/W =
    " PAYMENTSUM/CURRENCY. RSAQFPAIRS has no LID, and FLPOS is proven unique
    " only on a single-line list, so a pair is kept only when each index
    " matches exactly one column of the list, the roles fit (F with W, M with
    " E), and no other FPAIRS row gives the same column a different partner.
    " Public for ltcl_b6_pairing.
    CLASS-METHODS pair_references
      IMPORTING it_fpairs       TYPE ty_b6_fpairs
                it_ldesc        TYPE ty_b6_ldescs
                iv_list_id      TYPE rsaqldesc-lid
      RETURNING VALUE(rt_pairs) TYPE ty_b6_pairs.

  PRIVATE SECTION.
    " IV_WORKSPACE/IV_USERGROUP/IV_QUERYNAME -> SAP's typed names; EV_TEXT
    " is the INVALID_INPUT reason, initial when all three are valid.
    CLASS-METHODS check_names
      IMPORTING iv_workspace TYPE string
                iv_usergroup TYPE string
                iv_queryname TYPE string
      EXPORTING ev_ws_flag   TYPE aqadef-wsid
                ev_group     TYPE aqadef-bgname
                ev_query     TYPE aqadef-quname
                ev_name      TYPE string
                ev_text      TYPE string.

    " RSAQ_REMOTE_QUERY_FIELDLIST SEL_FIELDS; EV_ERROR QUERY_NOT_FOUND or
    " QUERY_UNAVAILABLE when it cannot be read.
    CLASS-METHODS read_selection_fields
      IMPORTING iv_ws_flag   TYPE aqadef-wsid
                iv_usergroup TYPE aqadef-bgname
                iv_query     TYPE aqadef-quname
                iv_name      TYPE string
      EXPORTING et_spn       TYPE ty_b6_spnames
                ev_error     TYPE string
                ev_text      TYPE string.

    CLASS-METHODS decode_selection
      IMPORTING it_wire  TYPE string_table
      EXPORTING et_sel   TYPE ty_b6_rsparams
                ev_error TYPE string.

    " Initial when SY-UNAME holds S_QUERY 23 or is assigned to the user
    " group, else the reason.
    CLASS-METHODS membership_denial
      IMPORTING iv_ws_flag     TYPE aqadef-wsid
                iv_usergroup   TYPE aqadef-bgname
      RETURNING VALUE(rv_text) TYPE string.

    CLASS-METHODS check_selection
      IMPORTING iv_ws_flag   TYPE aqadef-wsid
                iv_usergroup TYPE aqadef-bgname
                iv_query     TYPE aqadef-quname
                iv_name      TYPE string
                it_sel       TYPE ty_b6_rsparams
      EXPORTING ev_error     TYPE string
                ev_text      TYPE string.

    CLASS-METHODS capture
      IMPORTING ir_ldata    TYPE REF TO data
                it_ldesc    TYPE ty_b6_ldescs
                it_fpairs   TYPE ty_b6_fpairs
                iv_list_id  TYPE rsaqldesc-lid
                iv_max_rows TYPE i
      CHANGING  cs_result   TYPE ty_b6_result.

    " ET_FIELDS, EV_LIST_ID and EV_COLUMN_COUNT from the list table's line
    " type; ET_NUMERIC flags each column for to_text. Shared by capture and
    " the zero-row path.
    CLASS-METHODS describe_columns
      IMPORTING ir_ldata   TYPE REF TO data
                it_ldesc   TYPE ty_b6_ldescs
                it_fpairs  TYPE ty_b6_fpairs
                iv_list_id TYPE rsaqldesc-lid
      EXPORTING et_numeric TYPE ty_b6_flags
      CHANGING  cs_result  TYPE ty_b6_result.

    " NO_DATA_SELECTED: the generated report exports only its "empty" flag,
    " so RSAQ_QUERY_CALL fills neither LISTDESC, FPAIRS nor the list table.
    " The report's own API forms still give LISTDESC (%READ_LDESC) and the
    " list's line type (%GET_REF_TO_TABLE); FPAIRS has no such form.
    CLASS-METHODS describe_empty_list
      IMPORTING iv_ws_flag   TYPE aqadef-wsid
                iv_usergroup TYPE aqadef-bgname
                iv_query     TYPE aqadef-quname
      CHANGING  cs_result    TYPE ty_b6_result.


    " CONV gives the locale-independent value but puts a numeric sign at
    " the END (1000.00-); the wire wants it in front, as B5 does.
    CLASS-METHODS to_text
      IMPORTING iv_value       TYPE simple
                iv_numeric     TYPE abap_bool
      RETURNING VALUE(rv_text) TYPE string.
ENDCLASS.

CLASS lcl_b6_query IMPLEMENTATION.

  METHOD run.
    DATA lv_ws_flag TYPE aqadef-wsid.
    DATA lv_group   TYPE aqadef-bgname.
    DATA lv_query   TYPE aqadef-quname.
    DATA lv_name    TYPE string.
    DATA lt_sel     TYPE ty_b6_rsparams.
    DATA lv_dbacc   TYPE i VALUE 1000000000.
    DATA lr_ldata   TYPE REF TO data.
    DATA lv_list_id TYPE rsaqldesc-lid.
    DATA lt_ldesc   TYPE ty_b6_ldescs.
    DATA lt_fpairs  TYPE ty_b6_fpairs.
    DATA lv_sap     TYPE string.
    DATA lv_rc      TYPE i.

    check_names( EXPORTING iv_workspace = iv_workspace
                           iv_usergroup = iv_usergroup
                           iv_queryname = iv_queryname
                 IMPORTING ev_ws_flag   = lv_ws_flag
                           ev_group     = lv_group
                           ev_query     = lv_query
                           ev_name      = lv_name
                           ev_text      = rs_result-text ).
    IF rs_result-text IS INITIAL AND iv_max_rows < 1.
      rs_result-text = |IV_MAX_ROWS must be at least 1, got { iv_max_rows }.|.
    ENDIF.
    IF rs_result-text IS INITIAL.
      decode_selection( EXPORTING it_wire = it_selection IMPORTING et_sel = lt_sel ev_error = rs_result-text ).
    ENDIF.
    IF rs_result-text IS NOT INITIAL.
      rs_result-error = `INVALID_INPUT`.
      RETURN.
    ENDIF.
    IF iv_max_rows > gc_plaidcl_max_rows.
      rs_result-error = `MAX_ROWS_EXCEEDED`.
      rs_result-text  = |IV_MAX_ROWS { iv_max_rows } exceeds the maximum { gc_plaidcl_max_rows }.|.
      RETURN.
    ENDIF.

    " Before anything touches the query: reading its selection screen
    " already generates the report.
    rs_result-text = membership_denial( iv_ws_flag = lv_ws_flag iv_usergroup = lv_group ).
    IF rs_result-text IS NOT INITIAL.
      rs_result-error = `NOT_AUTHORIZED`.
      RETURN.
    ENDIF.

    check_selection( EXPORTING iv_ws_flag   = lv_ws_flag
                               iv_usergroup = lv_group
                               iv_query     = lv_query
                               iv_name      = lv_name
                               it_sel       = lt_sel
                     IMPORTING ev_error     = rs_result-error
                               ev_text      = rs_result-text ).
    IF rs_result-error IS NOT INITIAL.
      RETURN.
    ENDIF.

    LOOP AT lt_sel TRANSPORTING NO FIELDS WHERE kind = 'S'.
      lv_dbacc = 0.
      EXIT.
    ENDLOOP.

    CLEAR: sy-msgid, sy-msgno, sy-msgv1, sy-msgv2, sy-msgv3, sy-msgv4.
    CALL FUNCTION 'RSAQ_QUERY_CALL'
      EXPORTING
        workspace                   = lv_ws_flag
        query                       = lv_query
        usergroup                   = lv_group
        dbacc                       = lv_dbacc
        skip_selscreen              = 'X'
        data_to_memory              = 'X'
      IMPORTING
        ref_to_ldata                = lr_ldata
        list_id                     = lv_list_id
      TABLES
        selection_table             = lt_sel
        listdesc                    = lt_ldesc
        fpairs                      = lt_fpairs
      EXCEPTIONS
        no_usergroup                = 1
        no_query                    = 2
        query_locked                = 3
        generation_cancelled        = 4
        no_selection                = 5
        no_variant                  = 6
        just_via_variant            = 7
        no_submit_auth              = 8
        no_data_selected            = 9
        data_to_memory_not_possible = 10
        OTHERS                      = 11.
    lv_rc = sy-subrc.
    IF sy-msgid IS NOT INITIAL.
      MESSAGE ID sy-msgid TYPE 'I' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO lv_sap.
    ENDIF.

    CASE lv_rc.
      WHEN 0.
        IF lr_ldata IS BOUND.
          capture( EXPORTING ir_ldata    = lr_ldata
                             it_ldesc    = lt_ldesc
                             it_fpairs   = lt_fpairs
                             iv_list_id  = lv_list_id
                             iv_max_rows = iv_max_rows
                   CHANGING  cs_result   = rs_result ).
          RETURN.
        ENDIF.
        rs_result-error = `QUERY_UNAVAILABLE`.
        rs_result-text  = |{ lv_name } returned no data table. { lv_sap }|.
      WHEN 9.
        describe_empty_list( EXPORTING iv_ws_flag   = lv_ws_flag
                                       iv_usergroup = lv_group
                                       iv_query     = lv_query
                             CHANGING  cs_result    = rs_result ).
      WHEN 1 OR 2.
        rs_result-error = `QUERY_NOT_FOUND`.
        rs_result-text  = |{ lv_name } does not exist. { lv_sap }|.
      WHEN 8.
        rs_result-error = `NOT_AUTHORIZED`.
        rs_result-text  = |No S_PROGRAM authorization to submit the report of { lv_name }. { lv_sap }|.
      WHEN OTHERS.
        DATA(lv_reason) = SWITCH string( lv_rc
                            WHEN 3  THEN `locked for editing`
                            WHEN 4  THEN `report generation cancelled`
                            WHEN 5  THEN `no selection`
                            WHEN 6  THEN `variant missing`
                            WHEN 7  THEN `runs only via a variant`
                            WHEN 10 THEN `list cannot be passed as a table`
                            ELSE         `unexpected RSAQ_QUERY_CALL result` ).
        rs_result-error = `QUERY_UNAVAILABLE`.
        rs_result-text  = |{ lv_name } cannot run ({ lv_rc }): { lv_reason }. { lv_sap }|.
    ENDCASE.
  ENDMETHOD.

  METHOD decode_selection.
    DATA ls_sel       TYPE rsparams.
    DATA lv_name_len  TYPE i.
    DATA lv_low_len   TYPE i.
    DATA lv_high_len  TYPE i.

    CLEAR: et_sel, ev_error.
    DESCRIBE FIELD ls_sel-selname LENGTH lv_name_len IN CHARACTER MODE.
    DESCRIBE FIELD ls_sel-low LENGTH lv_low_len IN CHARACTER MODE.
    DESCRIBE FIELD ls_sel-high LENGTH lv_high_len IN CHARACTER MODE.

    LOOP AT it_wire INTO DATA(lv_line).
      DATA(lv_entry) = sy-tabix.
      DATA(lt_parts) = lcl_plaidcl_codec=>decode_row( lv_line ).
      IF lines( lt_parts ) <> 6.
        ev_error = |IT_SELECTION entry { lv_entry }: expected 6 codec fields | &&
                   |(SELNAME, KIND, SIGN, OPTION, LOW, HIGH), found { lines( lt_parts ) }.|.
        RETURN.
      ENDIF.
      DATA(lv_selname) = lt_parts[ 1 ].
      DATA(lv_kind)    = lt_parts[ 2 ].
      DATA(lv_sign)    = lt_parts[ 3 ].
      DATA(lv_option)  = lt_parts[ 4 ].

      IF lv_selname IS INITIAL OR strlen( lv_selname ) > lv_name_len
         OR strlen( lt_parts[ 5 ] ) > lv_low_len OR strlen( lt_parts[ 6 ] ) > lv_high_len.
        ev_error = |IT_SELECTION entry { lv_entry } [{ lv_selname }]: SELNAME must be 1 to { lv_name_len } | &&
                   |characters, LOW/HIGH at most { lv_low_len }.|.
        RETURN.
      ENDIF.
      " %SAVE, %PATH, %DOWN, ... steer the query's output, not its data.
      IF find( val = lv_selname sub = `%` ) = 0.
        ev_error = |IT_SELECTION entry { lv_entry } [{ lv_selname }]: output-control fields are not selections.|.
        RETURN.
      ENDIF.
      IF NOT ( ( lv_kind = `S` AND ( lv_sign = `I` OR lv_sign = `E` )
                 AND matches( val = lv_option regex = `EQ|NE|GT|GE|LT|LE|BT|NB|CP|NP` ) )
            OR ( lv_kind = `P` AND ( lv_sign IS INITIAL OR lv_sign = `I` )
                 AND ( lv_option IS INITIAL OR lv_option = `EQ` ) ) ).
        ev_error = |IT_SELECTION entry { lv_entry } [{ lv_selname }]: KIND/SIGN/OPTION [{ lv_kind }/{ lv_sign }/| &&
                   |{ lv_option }] invalid; use S with I or E and a standard option, or P.|.
        RETURN.
      ENDIF.

      CLEAR ls_sel.
      ls_sel-selname = lv_selname.
      ls_sel-kind    = lv_kind.
      ls_sel-sign    = lv_sign.
      ls_sel-option  = lv_option.
      ls_sel-low     = lt_parts[ 5 ].
      ls_sel-high    = lt_parts[ 6 ].
      APPEND ls_sel TO et_sel.
    ENDLOOP.
  ENDMETHOD.

  METHOD membership_denial.
    DATA lv_prefix  TYPE aqadef-pgname.
    DATA lv_ws      TYPE aqadef-wsid.
    DATA lv_all     TYPE c LENGTH 1 VALUE 'X'.
    DATA lt_ptab    TYPE abap_func_parmbind_tab.
    DATA lt_etab    TYPE abap_func_excpbind_tab.
    DATA lr_table   TYPE REF TO data.
    DATA lr_dbbn    TYPE REF TO data.
    FIELD-SYMBOLS <lt_dbbn>   TYPE ANY TABLE.
    FIELD-SYMBOLS <ls_member> TYPE any.
    FIELD-SYMBOLS <lv_group>  TYPE any.
    FIELD-SYMBOLS <lv_user>   TYPE any.

    " SAPMS38R: "Superuser sind in jeder Benutzergruppe".
    AUTHORITY-CHECK OBJECT 'S_QUERY' ID 'ACTVT' FIELD '23'.
    IF sy-subrc = 0.
      RETURN.
    ENDIF.

    rv_text = |User { sy-uname } is not assigned to user group { iv_usergroup } | &&
              |({ COND string( WHEN iv_ws_flag IS INITIAL THEN `standard` ELSE `global` ) } area) | &&
              |or the group does not exist|.

    " The catalog FM takes SAP's internal area code (WS_STANDARD /
    " WS_GLOBAL), unlike RSAQ_QUERY_CALL, which maps blank/non-blank itself.
    " The report-name decoder returns that code, so no value is assumed.
    lv_prefix = COND #( WHEN iv_ws_flag IS INITIAL THEN 'AQ00' ELSE 'AQZZ' ).
    CALL FUNCTION 'RSAQ_DECODE_REPORT_NAME'
      EXPORTING
        reportname = lv_prefix
      IMPORTING
        workspace  = lv_ws
      EXCEPTIONS
        OTHERS     = 1.
    IF sy-subrc <> 0.
      rv_text = |{ rv_text } (area code not decodable).|.
      RETURN.
    ENDIF.

    " The TABLES parameters are bound from the FM's own interface, so no
    " catalog structure name is hard-coded here.
    SELECT parameter, structure FROM fupararef
      WHERE funcname = 'RSAQ_IMPORT_USERGROUP_CATALOG'
        AND r3state  = 'A'
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
          rv_text = |{ rv_text } (catalog has no O_DBBN table).|.
          RETURN.
        ENDIF.
        INSERT VALUE #( name = 'I_WSPACE' kind = abap_func_exporting value = REF #( lv_ws ) ) INTO TABLE lt_ptab.
        INSERT VALUE #( name = 'I_ALL' kind = abap_func_exporting value = REF #( lv_all ) ) INTO TABLE lt_ptab.
        INSERT VALUE #( name = 'OTHERS' value = 1 ) INTO TABLE lt_etab.
        CALL FUNCTION 'RSAQ_IMPORT_USERGROUP_CATALOG'
          PARAMETER-TABLE lt_ptab
          EXCEPTION-TABLE lt_etab.
        IF sy-subrc <> 0.
          rv_text = |{ rv_text } (catalog read failed).|.
          RETURN.
        ENDIF.
      CATCH cx_sy_create_data_error cx_sy_dyn_call_error INTO DATA(lx_error).
        rv_text = |{ rv_text } (catalog unreadable: { lx_error->get_text( ) }).|.
        RETURN.
    ENDTRY.

    ASSIGN lr_dbbn->* TO <lt_dbbn>.
    LOOP AT <lt_dbbn> ASSIGNING <ls_member>.
      ASSIGN COMPONENT 'NUM' OF STRUCTURE <ls_member> TO <lv_group>.
      IF sy-subrc = 0.
        ASSIGN COMPONENT 'BNAME' OF STRUCTURE <ls_member> TO <lv_user>.
      ENDIF.
      IF sy-subrc <> 0.
        rv_text = |{ rv_text } (O_DBBN has no NUM/BNAME component).|.
        RETURN.
      ENDIF.
      IF <lv_group> = iv_usergroup AND <lv_user> = sy-uname.
        CLEAR rv_text.
        RETURN.
      ENDIF.
    ENDLOOP.
    rv_text = |{ rv_text }.|.
  ENDMETHOD.

  METHOD check_names.
    DATA lv_len TYPE i.

    CLEAR: ev_ws_flag, ev_group, ev_query, ev_name, ev_text.
    IF to_upper( iv_workspace ) = `GLOBAL`.
      ev_ws_flag = 'X'.
    ELSEIF iv_workspace IS NOT INITIAL AND to_upper( iv_workspace ) <> `STANDARD`.
      ev_text = |IV_WORKSPACE [{ iv_workspace }] must be STANDARD or GLOBAL.|.
      RETURN.
    ENDIF.
    " A longer name would be cut on assignment and address another query.
    DESCRIBE FIELD ev_group LENGTH lv_len IN CHARACTER MODE.
    IF iv_usergroup IS INITIAL OR strlen( iv_usergroup ) > lv_len.
      ev_text = |IV_USERGROUP [{ iv_usergroup }] must be 1 to { lv_len } characters.|.
      RETURN.
    ENDIF.
    DESCRIBE FIELD ev_query LENGTH lv_len IN CHARACTER MODE.
    IF iv_queryname IS INITIAL OR strlen( iv_queryname ) > lv_len.
      ev_text = |IV_QUERYNAME [{ iv_queryname }] must be 1 to { lv_len } characters.|.
      RETURN.
    ENDIF.
    ev_group = iv_usergroup.
    ev_query = iv_queryname.
    ev_name  = |{ COND string( WHEN ev_ws_flag IS INITIAL THEN `STANDARD` ELSE `GLOBAL` ) } query | &&
               |{ iv_usergroup }/{ iv_queryname }|.
  ENDMETHOD.

  METHOD read_selection_fields.
    DATA lv_rc  TYPE i.
    DATA lv_sap TYPE string.

    CLEAR: et_spn, ev_error, ev_text.
    CLEAR: sy-msgid, sy-msgno, sy-msgv1, sy-msgv2, sy-msgv3, sy-msgv4.
    " The read can generate the query's report; an E message there comes
    " back as ERROR_MESSAGE instead of ending the caller's RFC session.
    CALL FUNCTION 'RSAQ_REMOTE_QUERY_FIELDLIST'
      EXPORTING
        workspace     = iv_ws_flag
        query         = iv_query
        usergroup     = iv_usergroup
      TABLES
        sel_fields    = et_spn
      EXCEPTIONS
        no_usergroup  = 1
        no_query      = 2
        no_selscreen  = 3
        error_message = 5
        OTHERS        = 4.
    lv_rc = sy-subrc.
    IF lv_rc <> 0 AND sy-msgid IS NOT INITIAL.
      MESSAGE ID sy-msgid TYPE 'I' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO lv_sap.
    ENDIF.
    IF lv_rc = 1 OR lv_rc = 2.
      ev_error = `QUERY_NOT_FOUND`.
      ev_text  = |{ iv_name } does not exist.|.
    ELSEIF lv_rc <> 0.
      ev_error = `QUERY_UNAVAILABLE`.
      ev_text  = |The selection screen of { iv_name } could not be read ({ lv_rc }). { lv_sap }|.
    ENDIF.
  ENDMETHOD.

  METHOD describe_selection.
    DATA lv_ws_flag TYPE aqadef-wsid.
    DATA lv_group   TYPE aqadef-bgname.
    DATA lv_query   TYPE aqadef-quname.
    DATA lv_name    TYPE string.
    DATA lt_spn     TYPE ty_b6_spnames.

    check_names( EXPORTING iv_workspace = iv_workspace
                           iv_usergroup = iv_usergroup
                           iv_queryname = iv_queryname
                 IMPORTING ev_ws_flag   = lv_ws_flag
                           ev_group     = lv_group
                           ev_query     = lv_query
                           ev_name      = lv_name
                           ev_text      = rs_result-text ).
    IF rs_result-text IS NOT INITIAL.
      rs_result-error = `INVALID_INPUT`.
      RETURN.
    ENDIF.

    " Reading the selection screen generates the report: check first, as RUN does.
    rs_result-text = membership_denial( iv_ws_flag = lv_ws_flag iv_usergroup = lv_group ).
    IF rs_result-text IS NOT INITIAL.
      rs_result-error = `NOT_AUTHORIZED`.
      RETURN.
    ENDIF.

    read_selection_fields( EXPORTING iv_ws_flag   = lv_ws_flag
                                     iv_usergroup = lv_group
                                     iv_query     = lv_query
                                     iv_name      = lv_name
                           IMPORTING et_spn       = lt_spn
                                     ev_error     = rs_result-error
                                     ev_text      = rs_result-text ).
    IF rs_result-error IS NOT INITIAL.
      RETURN.
    ENDIF.

    LOOP AT lt_spn INTO DATA(ls_spn).
      " %ALV, %PATH, %SAVE ... steer the query's output; B6 refuses them.
      IF ls_spn-spname CP '%*'.
        CONTINUE.
      ENDIF.
      APPEND selection_field_row( ls_spn ) TO rs_result-fields.
    ENDLOOP.
  ENDMETHOD.

  METHOD selection_field_row.
    DATA lv_table    TYPE dd03l-tabname.
    DATA lv_field    TYPE dd03l-fieldname.
    DATA lv_rollname TYPE dd04l-rollname.
    DATA lv_sub_tab  TYPE string.
    DATA lv_sub_fld  TYPE string.
    DATA lt_notes    TYPE string_table.

    DATA(lv_fname) = to_upper( |{ is_spn-fname }| ).
    IF lv_fname IS INITIAL.
      APPEND `Query parameter without a DDIC reference.` TO lt_notes.
    ELSE.
      FIND PCRE `^(.+)-([^-]+)\z` IN lv_fname SUBMATCHES lv_sub_tab lv_sub_fld.
      IF sy-subrc = 0 AND strlen( lv_sub_tab ) <= 30 AND strlen( lv_sub_fld ) <= 30.
        lv_table = lv_sub_tab.
        lv_field = lv_sub_fld.
        SELECT SINGLE rollname FROM dd03l INTO @lv_rollname
          WHERE tabname = @lv_table AND fieldname = @lv_field AND as4local = 'A'.
      ELSEIF strlen( lv_fname ) <= 30.
        lv_rollname = lv_fname.
        SELECT SINGLE rollname FROM dd04l INTO @lv_rollname
          WHERE rollname = @lv_rollname AND as4local = 'A'.
        IF sy-subrc <> 0.
          CLEAR lv_rollname.
        ENDIF.
      ENDIF.
      IF lv_rollname IS INITIAL.
        APPEND |InfoSet field [{ lv_fname }] has no DDIC data element.| TO lt_notes.
      ENDIF.
    ENDIF.

    DATA(lv_text) = |{ is_spn-ftext }|.
    IF ( lv_text IS INITIAL OR lv_text = `.` ) AND lv_rollname IS NOT INITIAL.
      SELECT SINGLE scrtext_m FROM dd04t INTO @DATA(lv_scrtext)
        WHERE rollname = @lv_rollname AND ddlanguage = @sy-langu AND as4local = 'A'.
      lv_text = COND #( WHEN sy-subrc = 0 THEN |{ lv_scrtext }| ELSE `` ).
    ELSEIF lv_text = `.`.
      CLEAR lv_text.
    ENDIF.

    CASE is_spn-che_rad.
      WHEN 'C'.
        APPEND `Checkbox.` TO lt_notes.
      WHEN 'R'.
        APPEND |Radio button of group { is_spn-rgroup }.| TO lt_notes.
    ENDCASE.
    IF is_spn-nodisplay IS NOT INITIAL.
      APPEND `Hidden on the selection screen.` TO lt_notes.
    ENDIF.

    rv_row = lcl_plaidcl_codec=>encode_row( VALUE string_table(
      ( |{ is_spn-spname }| )
      ( |{ is_spn-kind }| )
      ( COND string( WHEN is_spn-obligatory IS NOT INITIAL THEN `X` ) )
      ( |{ lv_rollname }| )
      ( lv_text )
      ( concat_lines_of( table = lt_notes sep = ` ` ) )
      ( |{ is_spn-type }| )
      ( COND string( WHEN is_spn-length CO '0123456789' AND is_spn-length IS NOT INITIAL
                     THEN |{ CONV i( is_spn-length ) }| ) ) ) ).
  ENDMETHOD.

  METHOD check_selection.
    DATA lt_spn TYPE ty_b6_spnames.

    read_selection_fields( EXPORTING iv_ws_flag   = iv_ws_flag
                                     iv_usergroup = iv_usergroup
                                     iv_query     = iv_query
                                     iv_name      = iv_name
                           IMPORTING et_spn       = lt_spn
                                     ev_error     = ev_error
                                     ev_text      = ev_text ).
    IF ev_error IS NOT INITIAL.
      RETURN.
    ENDIF.

    LOOP AT it_sel INTO DATA(ls_sel).
      READ TABLE lt_spn INTO DATA(ls_spn) WITH KEY spname = ls_sel-selname.
      IF sy-subrc <> 0.
        ev_error = `INVALID_INPUT`.
        ev_text  = |Selection field [{ ls_sel-selname }] is not on the selection screen of { iv_name }.|.
        RETURN.
      ENDIF.
      IF ls_spn-kind <> ls_sel-kind.
        ev_error = `INVALID_INPUT`.
        ev_text  = |Selection field [{ ls_sel-selname }] of { iv_name } is KIND { ls_spn-kind }, not { ls_sel-kind }.|.
        RETURN.
      ENDIF.
    ENDLOOP.

    LOOP AT lt_spn INTO ls_spn WHERE obligatory <> space.
      LOOP AT it_sel TRANSPORTING NO FIELDS
           WHERE selname = ls_spn-spname AND ( kind = 'S' OR low IS NOT INITIAL ).
        EXIT.
      ENDLOOP.
      IF sy-subrc <> 0.
        ev_error = `INVALID_INPUT`.
        ev_text  = |Obligatory selection field [{ ls_spn-spname }] of { iv_name } has no value.|.
        RETURN.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD capture.
    CONSTANTS c_row_byte_budget TYPE int8 VALUE 33554432.
    DATA lt_numeric TYPE ty_b6_flags.
    DATA lt_values  TYPE string_table.
    DATA lv_col     TYPE i.
    DATA lv_bytes   TYPE int8.
    FIELD-SYMBOLS <lt_data>  TYPE STANDARD TABLE.
    FIELD-SYMBOLS <ls_line>  TYPE any.
    FIELD-SYMBOLS <lv_value> TYPE any.

    describe_columns( EXPORTING ir_ldata   = ir_ldata
                                it_ldesc   = it_ldesc
                                it_fpairs  = it_fpairs
                                iv_list_id = iv_list_id
                      IMPORTING et_numeric = lt_numeric
                      CHANGING  cs_result  = cs_result ).
    IF cs_result-error IS NOT INITIAL.
      RETURN.
    ENDIF.

    ASSIGN ir_ldata->* TO <lt_data>.
    LOOP AT <lt_data> ASSIGNING <ls_line>.
      IF lines( cs_result-rows ) = iv_max_rows.
        cs_result-truncated = abap_true.
        EXIT.
      ENDIF.
      CLEAR lt_values.
      DO cs_result-column_count TIMES.
        lv_col = sy-index.
        ASSIGN COMPONENT lv_col OF STRUCTURE <ls_line> TO <lv_value>.
        APPEND to_text( iv_value = <lv_value> iv_numeric = lt_numeric[ lv_col ] ) TO lt_values.
      ENDDO.
      DATA(lv_row) = lcl_plaidcl_codec=>encode_row( lt_values ).
      lv_bytes = lv_bytes + 2 * strlen( lv_row ).
      IF lv_bytes > c_row_byte_budget.
        cs_result-truncated = abap_true.
        EXIT.
      ENDIF.
      APPEND lv_row TO cs_result-rows.
    ENDLOOP.
  ENDMETHOD.

  METHOD describe_empty_list.
    DATA lv_prefix  TYPE aqadef-pgname.
    DATA lv_ws      TYPE aqadef-wsid.
    DATA lv_report  TYPE aqadef-pgname.
    DATA lv_lid     TYPE aql_lid.
    DATA lt_tldesc  TYPE rsaqtldesc.
    DATA lt_ldesc   TYPE ty_b6_ldescs.
    DATA lv_list_id TYPE rsaqldesc-lid.
    DATA lr_ldata   TYPE REF TO data.
    DATA lv_subrc   TYPE sy-subrc.
    DATA lt_numeric TYPE ty_b6_flags.

    " Report name as RSAQ_REMOTE_QUERY_FIELDLIST derives it: SAP's internal
    " area code (see membership_denial), then RSAQ_REPORT_NAME.
    lv_prefix = COND #( WHEN iv_ws_flag IS INITIAL THEN 'AQ00' ELSE 'AQZZ' ).
    CALL FUNCTION 'RSAQ_DECODE_REPORT_NAME'
      EXPORTING
        reportname = lv_prefix
      IMPORTING
        workspace  = lv_ws
      EXCEPTIONS
        OTHERS     = 1.
    IF sy-subrc <> 0.
      RETURN.
    ENDIF.
    CALL FUNCTION 'RSAQ_REPORT_NAME'
      EXPORTING
        workspace  = lv_ws
        usergroup  = iv_usergroup
        query      = iv_query
      IMPORTING
        reportname = lv_report
      EXCEPTIONS
        OTHERS     = 1.
    IF sy-subrc <> 0 OR lv_report IS INITIAL.
      RETURN.
    ENDIF.

    " The same PERFORM IN PROGRAM RSAQ_QUERY_CALL uses; IF FOUND keeps a
    " report generated without these forms a plain zero-row result.
    PERFORM %read_ldesc IN PROGRAM (lv_report) IF FOUND USING lv_lid lt_tldesc.
    IF lv_lid IS INITIAL OR lt_tldesc IS INITIAL.
      RETURN.
    ENDIF.
    lv_list_id = lv_lid.
    lt_ldesc   = lt_tldesc.
    PERFORM %get_ref_to_table IN PROGRAM (lv_report) IF FOUND USING lv_list_id lr_ldata lv_subrc.
    IF lv_subrc <> 0 OR lr_ldata IS NOT BOUND.
      RETURN.
    ENDIF.

    describe_columns( EXPORTING ir_ldata   = lr_ldata
                                it_ldesc   = lt_ldesc
                                it_fpairs  = VALUE #( )
                                iv_list_id = lv_list_id
                      IMPORTING et_numeric = lt_numeric
                      CHANGING  cs_result  = cs_result ).
    " A list shape capture refuses stays a zero-row success, as before.
    IF cs_result-error IS NOT INITIAL.
      CLEAR: cs_result-error, cs_result-text, cs_result-list_id, cs_result-column_count, cs_result-fields.
    ENDIF.
  ENDMETHOD.

  METHOD describe_columns.
    DATA lo_table TYPE REF TO cl_abap_tabledescr.
    DATA lo_elem  TYPE REF TO cl_abap_elemdescr.
    DATA ls_ldesc TYPE rsaqldesc.
    DATA lv_col   TYPE i.

    CLEAR et_numeric.
    cs_result-list_id = iv_list_id.
    lo_table ?= cl_abap_typedescr=>describe_by_data_ref( ir_ldata ).
    DATA(lo_line) = lo_table->get_table_line_type( ).
    IF lo_line->kind <> cl_abap_typedescr=>kind_struct.
      cs_result-error = `QUERY_UNAVAILABLE`.
      cs_result-text  = |List { iv_list_id } does not have structured lines.|.
      RETURN.
    ENDIF.
    DATA(lt_components) = CAST cl_abap_structdescr( lo_line )->get_components( ).
    IF lt_components IS INITIAL.
      cs_result-error = `QUERY_UNAVAILABLE`.
      cs_result-text  = |List { iv_list_id } has no columns.|.
      RETURN.
    ENDIF.

    DATA(lt_pairs) = pair_references( it_fpairs = it_fpairs it_ldesc = it_ldesc iv_list_id = iv_list_id ).

    LOOP AT lt_components INTO DATA(ls_component).
      lv_col = sy-tabix.
      IF ls_component-type->kind <> cl_abap_typedescr=>kind_elem.
        cs_result-error = `QUERY_UNAVAILABLE`.
        cs_result-text  = |List { iv_list_id } column { lv_col } [{ ls_component-name }] is not | &&
                          |elementary; this list shape is not supported.|.
        CLEAR cs_result-fields.
        RETURN.
      ENDIF.
      lo_elem ?= ls_component-type.
      DATA(lv_numeric) = xsdbool( lo_elem->type_kind CA 'PIFbs8ae' ).
      APPEND lv_numeric TO et_numeric.

      READ TABLE it_ldesc INTO ls_ldesc WITH KEY lid = iv_list_id fnameint = ls_component-name.
      IF sy-subrc <> 0.
        CLEAR ls_ldesc.
        ls_ldesc-ftyp = lo_elem->type_kind.
        ls_ldesc-flen = lo_elem->output_length.
        ls_ldesc-fdec = lo_elem->decimals.
      ENDIF.
      DATA(lv_rollname) = COND string( WHEN lo_elem->is_ddic_type( ) = abap_true
                                       THEN lo_elem->get_relative_name( ) ).
      DATA(lv_ref) = VALUE string( lt_pairs[ column = ls_component-name ]-ref OPTIONAL ).
      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ lv_col }| )
        ( CONV string( ls_component-name ) )
        ( |{ lv_rollname }| )
        ( CONV string( ls_ldesc-ftyp ) )
        ( |{ CONV i( ls_ldesc-flen ) }| )
        ( |{ CONV i( ls_ldesc-fdec ) }| )
        ( CONV string( ls_ldesc-fdesc ) )
        ( CONV string( ls_ldesc-fcur ) )
        ( lv_ref ) ) ) TO cs_result-fields.
    ENDLOOP.
    cs_result-column_count = lines( lt_components ).
  ENDMETHOD.

  METHOD pair_references.
    DATA ls_pair   TYPE ty_b6_pair.
    DATA ls_ldesc  TYPE rsaqldesc.
    DATA lv_role_a TYPE rsaqldesc-fcur.
    DATA lv_role_u TYPE rsaqldesc-fcur.
    DATA lv_hits_a TYPE i.
    DATA lv_hits_u TYPE i.
    FIELD-SYMBOLS <ls_fpair> TYPE rsaqfpairs.
    FIELD-SYMBOLS <ls_known> TYPE ty_b6_pair.

    LOOP AT it_fpairs ASSIGNING <ls_fpair>.
      CLEAR: ls_pair, lv_role_a, lv_role_u, lv_hits_a, lv_hits_u.
      LOOP AT it_ldesc INTO ls_ldesc WHERE lid = iv_list_id.
        IF ls_ldesc-flpos = <ls_fpair>-index_a.
          lv_hits_a      = lv_hits_a + 1.
          ls_pair-column = ls_ldesc-fnameint.
          lv_role_a      = ls_ldesc-fcur.
        ENDIF.
        IF ls_ldesc-flpos = <ls_fpair>-index_u.
          lv_hits_u   = lv_hits_u + 1.
          ls_pair-ref = ls_ldesc-fnameint.
          lv_role_u   = ls_ldesc-fcur.
        ENDIF.
      ENDLOOP.
      " A position shared by several columns (multi-line list) names no
      " column for certain: leave it unpaired rather than pick one.
      IF lv_hits_a <> 1 OR lv_hits_u <> 1
         OR NOT ( ( lv_role_a = 'F' AND lv_role_u = 'W' ) OR ( lv_role_a = 'M' AND lv_role_u = 'E' ) ).
        CONTINUE.
      ENDIF.
      ASSIGN rt_pairs[ column = ls_pair-column ] TO <ls_known>.
      IF sy-subrc <> 0.
        INSERT ls_pair INTO TABLE rt_pairs.
      ELSEIF <ls_known>-ref <> ls_pair-ref.
        CLEAR <ls_known>-ref.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD to_text.
    rv_text = CONV string( iv_value ).
    IF iv_numeric = abap_false.
      RETURN.
    ENDIF.
    CONDENSE rv_text NO-GAPS.
    DATA(lv_len) = strlen( rv_text ).
    IF lv_len > 1 AND substring( val = rv_text off = lv_len - 1 len = 1 ) = `-`.
      rv_text = |-{ substring( val = rv_text len = lv_len - 1 ) }|.
    ENDIF.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Unit tests on lcl_b6_query itself, so they live in the group.
*& Run: ADT abapunit testruns against /sap/bc/adt/functions/groups/z_plaidcl.
*&---------------------------------------------------------------------*
CLASS ltcl_b6_pairing DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS pair_within_its_list          FOR TESTING.
    METHODS duplicate_flpos_left_unpaired FOR TESTING.
    METHODS conflicting_partner_unpaired  FOR TESTING.
ENDCLASS.

CLASS ltcl_b6_pairing IMPLEMENTATION.

  " BT/D1's shape (FPAIRS 0006/0007), plus a T01 list reusing positions 6
  " and 7: only the requested list's columns count.
  METHOD pair_within_its_list.
    DATA(lt_pairs) = lcl_b6_query=>pair_references(
      it_fpairs  = VALUE #( ( index_a = '0006' index_u = '0007' ) )
      it_ldesc   = VALUE #( ( lid = 'G00' flpos = '0005' fnameint = 'SPFLI-CITYTO' )
                            ( lid = 'G00' flpos = '0006' fnameint = 'SFLIGHT-PAYMENTSUM' fcur = 'F' )
                            ( lid = 'G00' flpos = '0007' fnameint = 'SFLIGHT-CURRENCY-0106' fcur = 'W' )
                            ( lid = 'T01' flpos = '0006' fnameint = 'T01-SFLIGHT-PAYMENTSUM' fcur = 'F' )
                            ( lid = 'T01' flpos = '0007' fnameint = 'T01-SFLIGHT-CURRENCY' fcur = 'W' ) )
      iv_list_id = CONV #( 'G00' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_pairs
      exp = VALUE ty_b6_pairs( ( column = `SFLIGHT-PAYMENTSUM` ref = `SFLIGHT-CURRENCY-0106` ) )
      msg = 'G00 PAYMENTSUM pairs with the G00 column at FLPOS 7 only' ).
  ENDMETHOD.

  " A multi-line list whose second line reuses positions 6 and 7. The
  " last-match-wins pairing gave SBOOK-LOCCURAM -> SBOOK-FORCURKEY and
  " SBOOK-FORCURAM -> SBOOK-FORCURKEY; neither position names one column.
  METHOD duplicate_flpos_left_unpaired.
    DATA(lt_pairs) = lcl_b6_query=>pair_references(
      it_fpairs  = VALUE #( ( index_a = '0006' index_u = '0007' )
                            ( index_a = '0009' index_u = '0007' ) )
      it_ldesc   = VALUE #( ( lid = 'G00' flpos = '0006' fnameint = 'SFLIGHT-PAYMENTSUM' fcur = 'F' )
                            ( lid = 'G00' flpos = '0007' fnameint = 'SFLIGHT-CURRENCY' fcur = 'W' )
                            ( lid = 'G00' flpos = '0006' fnameint = 'SBOOK-LOCCURAM' fcur = 'F' )
                            ( lid = 'G00' flpos = '0007' fnameint = 'SBOOK-FORCURKEY' fcur = 'W' )
                            ( lid = 'G00' flpos = '0009' fnameint = 'SBOOK-FORCURAM' fcur = 'F' ) )
      iv_list_id = CONV #( 'G00' ) ).
    cl_abap_unit_assert=>assert_initial( act = lt_pairs msg = 'an FLPOS shared by two columns must pair nothing' ).
  ENDMETHOD.

  METHOD conflicting_partner_unpaired.
    DATA(lt_pairs) = lcl_b6_query=>pair_references(
      it_fpairs  = VALUE #( ( index_a = '0006' index_u = '0007' )
                            ( index_a = '0006' index_u = '0008' ) )
      it_ldesc   = VALUE #( ( lid = 'G00' flpos = '0006' fnameint = 'SFLIGHT-PAYMENTSUM' fcur = 'F' )
                            ( lid = 'G00' flpos = '0007' fnameint = 'SFLIGHT-CURRENCY' fcur = 'W' )
                            ( lid = 'G00' flpos = '0008' fnameint = 'SCARR-CURRCODE' fcur = 'W' ) )
      iv_list_id = CONV #( 'G00' ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_pairs
      exp = VALUE ty_b6_pairs( ( column = `SFLIGHT-PAYMENTSUM` ) )
      msg = 'two FPAIRS partners for one column must leave REF_COLUMN empty' ).
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& Z_PLAIDCL_B6_QUERY_WORKER -- remote-enabled, group Z_PLAIDCL.
*& Runs every check itself; B6 calls it only via DESTINATION 'NONE'.
*&---------------------------------------------------------------------*
FUNCTION z_plaidcl_b6_query_worker.
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
*"----------------------------------------------------------------------



  DATA lv_v1 TYPE symsgv.
  DATA lv_v2 TYPE symsgv.
  DATA lv_v3 TYPE symsgv.
  DATA lv_v4 TYPE symsgv.

  CLEAR: ev_list_id, ev_row_count, ev_column_count, ev_truncated, et_fields, et_rows.

  DATA(ls_result) = lcl_b6_query=>run( iv_workspace = iv_workspace
                                       iv_usergroup = iv_usergroup
                                       iv_queryname = iv_queryname
                                       iv_max_rows  = iv_max_rows
                                       it_selection = it_selection ).
  IF ls_result-error IS INITIAL.
    ev_list_id      = ls_result-list_id.
    ev_row_count    = lines( ls_result-rows ).
    ev_column_count = ls_result-column_count.
    ev_truncated    = ls_result-truncated.
    et_fields       = ls_result-fields.
    et_rows         = ls_result-rows.
    RETURN.
  ENDIF.

  lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = ls_result-text
                                 IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
  CASE ls_result-error.
    WHEN `NOT_AUTHORIZED`.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
    WHEN `QUERY_NOT_FOUND`.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING query_not_found.
    WHEN `QUERY_UNAVAILABLE`.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING query_unavailable.
    WHEN `MAX_ROWS_EXCEEDED`.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING max_rows_exceeded.
    WHEN OTHERS.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDCASE.

ENDFUNCTION.
