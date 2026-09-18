*&---------------------------------------------------------------------*
*& sc-28966 Z_PLAIDCL_B6_SELSCREEN -- an SQ01 query's selection fields.
*&---------------------------------------------------------------------*
* The query counterpart of B13: what a filter form for B6 needs, read
* from RSAQ_REMOTE_QUERY_FIELDLIST SEL_FIELDS (the list B6's own
* selection check uses).
*
* AUTHORIZATION: B6's rule and nothing else. S_QUERY ACTVT 23, or
* assignment to the user group in the requested area (lcl_b6_query
* membership_denial); checked before the field list is read, because
* that read generates the query's report as SQ01 does.
*
* WIRE: ET_FIELDS, one lcl_plaidcl_codec row per selection field in
* SEL_FIELDS order:
*   SELNAME|KIND|OBLIGATORY|ROLLNAME|DESCRIPTION|NOTE|DATATYPE|LENGTH
*   SELNAME     the name B6's IT_SELECTION takes (e.g. CARRID, SP$00001).
*   KIND        S (SELECT-OPTIONS) or P (PARAMETERS), as IT_SELECTION.
*   OBLIGATORY  'X' or empty.
*   ROLLNAME    DDIC data element of the InfoSet field (DD03L for
*               TABLE-FIELD, DD04L for a bare name); empty when the field
*               has none (a query parameter, a table DD03L does not know).
*   DESCRIPTION the query's field text; when it is empty or '.', the
*               data element's medium text in the logon language.
*   NOTE        why ROLLNAME is empty, "Checkbox.", "Radio button of group
*               G.", "Hidden on the selection screen.", space-separated.
*   DATATYPE    ABAP type letter (C N D T P I ...), LENGTH its output
*               length (DATS 10, TIMS 8), or empty.
* Output controls (%ALV, %PATH, %SAVE ...) are not returned; B6 refuses
* them. EV_FIELD_COUNT is authoritative.
* Errors are MESSAGE e001(00) ... RAISING (Contract 3).
*&---------------------------------------------------------------------*
CLASS ltcl_b6_selscreen DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS obligatory_and_rollname  FOR TESTING.
    METHODS parameter_without_ddic   FOR TESTING.
    METHODS dot_text_takes_ddic_text FOR TESTING.
ENDCLASS.

CLASS ltcl_b6_selscreen IMPLEMENTATION.

  METHOD obligatory_and_rollname.
    DATA(lt_parts) = lcl_plaidcl_codec=>decode_row( lcl_b6_query=>selection_field_row(
      VALUE #( kind = 'S' spname = 'S_X' obligatory = 'X' fname = 'SPFLI-CARRID'
               ftext = 'Air|line' type = 'C' length = '003' ) ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_parts
      exp = VALUE string_table( ( `S_X` ) ( `S` ) ( `X` ) ( `S_CARR_ID` ) ( `Air|line` ) ( `` ) ( `C` ) ( `3` ) ) ).
  ENDMETHOD.

  METHOD parameter_without_ddic.
    DATA(lt_parts) = lcl_plaidcl_codec=>decode_row( lcl_b6_query=>selection_field_row(
      VALUE #( kind = 'P' spname = 'PA_CANC' ftext = 'Also display' type = 'C' length = '001' che_rad = 'C' ) ) ).
    cl_abap_unit_assert=>assert_equals(
      act = lt_parts
      exp = VALUE string_table( ( `PA_CANC` ) ( `P` ) ( `` ) ( `` ) ( `Also display` )
                                ( `Query parameter without a DDIC reference. Checkbox.` ) ( `C` ) ( `1` ) ) ).
    lt_parts = lcl_plaidcl_codec=>decode_row( lcl_b6_query=>selection_field_row(
      VALUE #( kind = 'S' spname = 'SP$00001' fname = 'ZZ_NO_SUCH_TABLE-NOFIELD' ftext = '.' type = 'C' length = '003' ) ) ).
    cl_abap_unit_assert=>assert_equals( act = lt_parts[ 4 ] exp = `` ).
    cl_abap_unit_assert=>assert_equals( act = lt_parts[ 5 ] exp = `` ).
    cl_abap_unit_assert=>assert_equals( act = lt_parts[ 6 ] exp = `InfoSet field [ZZ_NO_SUCH_TABLE-NOFIELD] has no DDIC data element.` ).
  ENDMETHOD.

  METHOD dot_text_takes_ddic_text.
    SELECT SINGLE scrtext_m FROM dd04t INTO @DATA(lv_expected)
      WHERE rollname = 'S_CARR_ID' AND ddlanguage = @sy-langu AND as4local = 'A'.
    DATA(lt_parts) = lcl_plaidcl_codec=>decode_row( lcl_b6_query=>selection_field_row(
      VALUE #( kind = 'S' spname = 'CARRID' fname = 'SPFLI-CARRID' ftext = '.' type = 'C' length = '003' ) ) ).
    cl_abap_unit_assert=>assert_not_initial( act = lv_expected msg = 'S_CARR_ID has a DD04T text in the logon language' ).
    cl_abap_unit_assert=>assert_equals( act = lt_parts[ 5 ] exp = |{ lv_expected }| ).
  ENDMETHOD.

ENDCLASS.

FUNCTION z_plaidcl_b6_selscreen.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_WORKSPACE) TYPE  STRING DEFAULT 'STANDARD'
*"     VALUE(IV_USERGROUP) TYPE  STRING
*"     VALUE(IV_QUERYNAME) TYPE  STRING
*"  EXPORTING
*"     VALUE(EV_FIELD_COUNT) TYPE  I
*"     VALUE(ET_FIELDS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"      QUERY_NOT_FOUND
*"      NOT_AUTHORIZED
*"      QUERY_UNAVAILABLE
*"----------------------------------------------------------------------



  DATA lv_v1 TYPE symsgv.
  DATA lv_v2 TYPE symsgv.
  DATA lv_v3 TYPE symsgv.
  DATA lv_v4 TYPE symsgv.

  CLEAR: ev_field_count, et_fields.

  DATA(ls_result) = lcl_b6_query=>describe_selection( iv_workspace = iv_workspace
                                                      iv_usergroup = iv_usergroup
                                                      iv_queryname = iv_queryname ).
  IF ls_result-error IS INITIAL.
    et_fields      = ls_result-fields.
    ev_field_count = lines( et_fields ).
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
    WHEN OTHERS.
      MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 RAISING invalid_input.
  ENDCASE.

ENDFUNCTION.
