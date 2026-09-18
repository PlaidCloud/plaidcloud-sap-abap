*&---------------------------------------------------------------------*
*& sc-27768 (D6 variant picker) -- B14 report variants, group Z_PLAIDCL.
*&---------------------------------------------------------------------*
* Z_PLAIDCL_B14_VARIANTS        lists a report's saved variants.
* Z_PLAIDCL_B14_VARIANT_VALUES  returns one variant's selection values.
* Both are remote-enabled and take exactly one of IV_TCODE / IV_REPORT,
* resolved as B7 does (TSTC-PGMNA).
*
* AUTHORIZATION: Z_PLAIDCL_B10_CHECK_PROGRAM, B7's run check (S_TCODE and
* S_PROGRAM SUBMIT on the program's authorization group), before anything
* about the program or its variants is read. Seeing a variant is scoped to
* whoever may run the report with it; PlaidCloud adds no gate of its own.
*
* LIST: VARID rows of the logon client, ordered by name. System variants
* (SAP& and CUS&, maintained in client 000) are excluded. TEXT is VARIT in
* the logon language, else the lowest maintained language key, else empty.
* PROTECTED is VARID-PROTECTED: only its creator may change it; anyone
* passing the gate may still read and use it, as in SE38.
* BACKGROUND_ONLY is VARID-ENVIRONMNT = 'B' (usable only in a job).
*
* VALUES: SAP's RS_VARIANT_CONTENTS, read from VALUTABL (LOW/HIGH C(255)),
* which also resolves a variant's selection variables (dynamic dates,
* TVARVC) to today's values. A row is returned for every selection field
* the variant stores except a SELECT-OPTIONS field with no value (SIGN and
* OPTION both empty), which RS_VARIANT_CONTENTS lists as a placeholder and
* SUBMIT would refuse. A PARAMETERS row, which SAP stores with SIGN/OPTION
* blank, is returned as I/EQ, the form B7's IT_SELECTION requires. A LOW
* or HIGH longer than B7 accepts (45) refuses the whole variant with
* INVALID_INPUT naming the field; a value is never returned truncated.
* Some SAP reports store internal names that are not on the selection
* screen ($GREP, %TIME on SAPICDT_); B7 refuses a name its selection
* screen lacks, so the caller drops those rows before a run.
*
* WIRE (lcl_plaidcl_codec rows):
*   ET_VARIANTS   VARIANT|TEXT|PROTECTED|BACKGROUND_ONLY|CREATED_BY|
*                 CHANGED_BY|CHANGED_ON
*                 flags 'X' or empty; CHANGED_ON YYYYMMDD
*   ET_SELECTION  SELNAME|KIND|SIGN|OPTION|LOW|HIGH
*                 B7's IT_SELECTION shape, values in SAP's internal format,
*                 so a row can be sent back to B7/B12 unchanged or edited.
* Errors are MESSAGE e001(00) ... RAISING (Contract 3).
*&---------------------------------------------------------------------*

TYPES ty_b14_params TYPE STANDARD TABLE OF rsparams WITH DEFAULT KEY.
TYPES ty_b14_params_l TYPE STANDARD TABLE OF rsparamsl WITH DEFAULT KEY.

TYPES: BEGIN OF ty_b14_resolved,
         program TYPE programm,
         error   TYPE string,
         text    TYPE string,
       END OF ty_b14_resolved.

TYPES: BEGIN OF ty_b14_values,
         rows  TYPE string_table,
         error TYPE string,
         text  TYPE string,
       END OF ty_b14_values.

CLASS lcl_b14_variants DEFINITION FINAL.
  PUBLIC SECTION.
    " B7 IT_SELECTION's LOW/HIGH limit (RSPARAMS C(45)).
    CONSTANTS c_max_value_len TYPE i VALUE 45.

    " RS-ERROR is the exception key (INVALID_INPUT, NOT_FOUND,
    " NOT_AUTHORIZED), initial when the program is resolved and granted.
    CLASS-METHODS resolve
      IMPORTING iv_tcode     TYPE tcode
                iv_report    TYPE programm
      RETURNING VALUE(rs)    TYPE ty_b14_resolved.

    CLASS-METHODS list
      IMPORTING iv_program     TYPE programm
      RETURNING VALUE(rt_rows) TYPE string_table.

    CLASS-METHODS is_system_variant
      IMPORTING iv_variant    TYPE variant
      RETURNING VALUE(rv_yes) TYPE abap_bool.

    " RS-ERROR is INVALID_INPUT when a value exceeds c_max_value_len.
    CLASS-METHODS encode_values
      IMPORTING it_params  TYPE ty_b14_params_l
      RETURNING VALUE(rs)  TYPE ty_b14_values.
ENDCLASS.

CLASS lcl_b14_variants IMPLEMENTATION.

  METHOD resolve.
    DATA lv_pgmna  TYPE tstc-pgmna.
    DATA lv_exists TYPE trdir-name.
    DATA lv_reason TYPE string.

    IF ( iv_tcode IS INITIAL AND iv_report IS INITIAL )
       OR ( iv_tcode IS NOT INITIAL AND iv_report IS NOT INITIAL ).
      rs-error = `INVALID_INPUT`.
      rs-text  = `Supply exactly one of IV_TCODE / IV_REPORT.`.
      RETURN.
    ENDIF.

    IF iv_report IS NOT INITIAL.
      rs-program = iv_report.
    ELSE.
      SELECT SINGLE pgmna FROM tstc INTO lv_pgmna WHERE tcode = iv_tcode.
      IF sy-subrc <> 0 OR lv_pgmna IS INITIAL.
        rs-error = `NOT_FOUND`.
        rs-text  = |Transaction [{ iv_tcode }] not found or has no report program (TSTC-PGMNA).|.
        RETURN.
      ENDIF.
      rs-program = lv_pgmna.
    ENDIF.

    " The gate runs before any read of the program itself.
    CALL FUNCTION 'Z_PLAIDCL_B10_CHECK_PROGRAM'
      EXPORTING
        iv_program        = rs-program
        iv_tcode          = iv_tcode
      EXCEPTIONS
        not_authorized    = 1
        program_not_found = 2
        OTHERS            = 3.
    CASE sy-subrc.
      WHEN 0.
      WHEN 2.
        rs-error = `NOT_FOUND`.
        rs-text  = |Program [{ rs-program }] not found (authorization gate).|.
        RETURN.
      WHEN OTHERS.
        rs-error = `NOT_AUTHORIZED`.
        CONCATENATE sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO lv_reason RESPECTING BLANKS.
        rs-text = replace( val = lv_reason pcre = `\s+$` with = `` ).
        IF rs-text IS INITIAL.
          rs-text = |Not authorized to run program [{ rs-program }] (tcode [{ iv_tcode }]).|.
        ENDIF.
        RETURN.
    ENDCASE.

    SELECT SINGLE name FROM trdir INTO lv_exists WHERE name = rs-program.
    IF sy-subrc <> 0.
      rs-error = `NOT_FOUND`.
      rs-text  = |Program [{ rs-program }] not found in TRDIR.|.
    ENDIF.
  ENDMETHOD.

  METHOD is_system_variant.
    rv_yes = xsdbool( iv_variant CP 'SAP&*' OR iv_variant CP 'CUS&*' ).
  ENDMETHOD.

  METHOD list.
    SELECT variant, protected, environmnt, ename, aename, aedat
      FROM varid
      WHERE report = @iv_program
      ORDER BY variant
      INTO TABLE @DATA(lt_varid).
    " Ordered, so the fallback text is the lowest language key, every call.
    SELECT langu, variant, vtext
      FROM varit
      WHERE report = @iv_program
      ORDER BY variant, langu
      INTO TABLE @DATA(lt_varit).

    LOOP AT lt_varid INTO DATA(ls_varid).
      IF is_system_variant( ls_varid-variant ) = abap_true.
        CONTINUE.
      ENDIF.
      DATA(lv_text) = VALUE string( lt_varit[ variant = ls_varid-variant langu = sy-langu ]-vtext OPTIONAL ).
      IF lv_text IS INITIAL.
        lv_text = VALUE #( lt_varit[ variant = ls_varid-variant ]-vtext OPTIONAL ).
      ENDIF.
      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ ls_varid-variant }| )
        ( lv_text )
        ( |{ ls_varid-protected }| )
        ( COND string( WHEN ls_varid-environmnt = 'B' THEN `X` ) )
        ( |{ ls_varid-ename }| )
        ( |{ ls_varid-aename }| )
        ( |{ ls_varid-aedat }| ) ) ) TO rt_rows.
    ENDLOOP.
  ENDMETHOD.

  METHOD encode_values.
    LOOP AT it_params INTO DATA(ls_param).
      IF ls_param-kind = 'S' AND ls_param-sign IS INITIAL AND ls_param-option IS INITIAL.
        CONTINUE.
      ENDIF.
      IF strlen( ls_param-low ) > c_max_value_len OR strlen( ls_param-high ) > c_max_value_len.
        CLEAR rs-rows.
        rs-error = `INVALID_INPUT`.
        rs-text  = |Variant value of [{ ls_param-selname }] is | &&
                   |{ nmax( val1 = strlen( ls_param-low ) val2 = strlen( ls_param-high ) ) } characters; | &&
                   |IT_SELECTION takes at most { c_max_value_len }, so the variant is refused, not truncated.|.
        RETURN.
      ENDIF.
      " SAP stores a PARAMETERS value with SIGN/OPTION blank; B7 and B6 take I/EQ.
      IF ls_param-kind = 'P'.
        ls_param-sign   = COND #( WHEN ls_param-sign IS INITIAL THEN 'I' ELSE ls_param-sign ).
        ls_param-option = COND #( WHEN ls_param-option IS INITIAL THEN 'EQ' ELSE ls_param-option ).
      ENDIF.
      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ ls_param-selname }| ) ( |{ ls_param-kind }| ) ( |{ ls_param-sign }| )
        ( |{ ls_param-option }| ) ( |{ ls_param-low }| ) ( |{ ls_param-high }| ) ) ) TO rs-rows.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

FUNCTION z_plaidcl_b14_variants.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_TCODE) TYPE  TCODE OPTIONAL
*"     VALUE(IV_REPORT) TYPE  PROGRAMM OPTIONAL
*"  EXPORTING
*"     VALUE(EV_PROGRAM) TYPE  PROGRAMM
*"     VALUE(EV_VARIANT_COUNT) TYPE  I
*"     VALUE(ET_VARIANTS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      NOT_FOUND
*"      NOT_AUTHORIZED
*"----------------------------------------------------------------------



  DATA lv_v1 TYPE symsgv.
  DATA lv_v2 TYPE symsgv.
  DATA lv_v3 TYPE symsgv.
  DATA lv_v4 TYPE symsgv.

  CLEAR: ev_program, ev_variant_count, et_variants.

  DATA(ls_resolved) = lcl_b14_variants=>resolve( iv_tcode = iv_tcode iv_report = iv_report ).
  IF ls_resolved-error IS NOT INITIAL.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = ls_resolved-text
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    CASE ls_resolved-error.
      WHEN `NOT_FOUND`.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_found.
      WHEN `NOT_AUTHORIZED`.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING not_authorized.
      WHEN OTHERS.
        MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
    ENDCASE.
  ENDIF.

  ev_program        = ls_resolved-program.
  et_variants       = lcl_b14_variants=>list( ls_resolved-program ).
  ev_variant_count  = lines( et_variants ).

ENDFUNCTION.
