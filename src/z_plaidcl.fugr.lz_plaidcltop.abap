FUNCTION-POOL z_plaidcl.

INCLUDE z_plaidcl_stage_types.

CONSTANTS gc_plaidcl_max_rows TYPE i VALUE 50000.

CLASS lcl_plaidcl_codec DEFINITION FINAL.
  PUBLIC SECTION.
    " Field delimiter |. Escapes: \ -> \\, | -> \|, LF -> \n, CR -> \r,
    " TAB -> \t, U+0000 -> \0. decode_row returns an INITIAL table for a
    " malformed line (dangling or unknown escape).
    " A ROW ALWAYS HAS AT LEAST ONE FIELD: encode_row( [''] ) = `` and
    " decode_row( `` ) = [''], so an empty IT_VALUES is invalid and no
    " caller encodes one.
    " An encoded line never contains LF, CR, TAB or U+0000, so it is safe
    " in JSON and PostgreSQL JSONB. It is NOT necessarily printable: other
    " control characters (U+0001..U+001F, U+007F) pass through unescaped.
    CLASS-METHODS encode_row   IMPORTING it_values TYPE string_table RETURNING VALUE(rv_line)   TYPE string.
    CLASS-METHODS decode_row   IMPORTING iv_line   TYPE string       RETURNING VALUE(rt_values) TYPE string_table.
    CLASS-METHODS encode_token IMPORTING it_parts  TYPE string_table RETURNING VALUE(rv_token)  TYPE string.
    CLASS-METHODS decode_token IMPORTING iv_token  TYPE string       RETURNING VALUE(rt_parts)  TYPE string_table.
ENDCLASS.

CLASS lcl_plaidcl_codec IMPLEMENTATION.
  METHOD encode_row.
    DATA lv_cr  TYPE string.
    DATA lv_sep TYPE string.
    lv_cr = substring( val = cl_abap_char_utilities=>cr_lf len = 1 ).
    LOOP AT it_values INTO DATA(lv_value).
      " Backslash first, so the escapes added below are not re-escaped.
      REPLACE ALL OCCURRENCES OF `\` IN lv_value WITH `\\`.
      REPLACE ALL OCCURRENCES OF `|` IN lv_value WITH `\|`.
      REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>newline IN lv_value WITH `\n`.
      REPLACE ALL OCCURRENCES OF lv_cr IN lv_value WITH `\r`.
      REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>horizontal_tab IN lv_value WITH `\t`.
      REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>minchar IN lv_value WITH `\0`.
      rv_line = rv_line && lv_sep && lv_value.
      lv_sep = `|`.
    ENDLOOP.
  ENDMETHOD.

  METHOD decode_row.
    DATA lv_value TYPE string.
    DATA lv_esc   TYPE string.
    DATA lv_pos   TYPE i.
    DATA lv_hit   TYPE i.
    DATA lv_len   TYPE i.

    lv_len = strlen( iv_line ).
    DO.
      lv_hit = -1.
      IF lv_pos < lv_len.
        lv_hit = find( val = iv_line regex = `[\\|]` off = lv_pos ).
      ENDIF.
      IF lv_hit < 0.
        IF lv_pos < lv_len.
          lv_value = lv_value && substring( val = iv_line off = lv_pos ).
        ENDIF.
        APPEND lv_value TO rt_values.
        RETURN.
      ENDIF.

      lv_value = lv_value && substring( val = iv_line off = lv_pos len = lv_hit - lv_pos ).
      lv_esc = substring( val = iv_line off = lv_hit len = 1 ).
      IF lv_esc = `|`.
        APPEND lv_value TO rt_values.
        CLEAR lv_value.
        lv_pos = lv_hit + 1.
        CONTINUE.
      ENDIF.

      IF lv_hit + 1 >= lv_len.
        CLEAR rt_values.
        RETURN.
      ENDIF.
      lv_esc = substring( val = iv_line off = lv_hit + 1 len = 1 ).
      CASE lv_esc.
        WHEN `\`.
          lv_value = lv_value && `\`.
        WHEN `|`.
          lv_value = lv_value && `|`.
        WHEN `n`.
          lv_value = lv_value && cl_abap_char_utilities=>newline.
        WHEN `r`.
          lv_value = lv_value && substring( val = cl_abap_char_utilities=>cr_lf len = 1 ).
        WHEN `t`.
          lv_value = lv_value && cl_abap_char_utilities=>horizontal_tab.
        WHEN `0`.
          lv_value = lv_value && cl_abap_char_utilities=>minchar.
        WHEN OTHERS.
          CLEAR rt_values.
          RETURN.
      ENDCASE.
      lv_pos = lv_hit + 2.
    ENDDO.
  ENDMETHOD.

  METHOD encode_token.
    rv_token = `K1|` && encode_row( it_parts ).
  ENDMETHOD.

  METHOD decode_token.
    DATA lv_body TYPE string.
    IF strlen( iv_token ) < 3.
      RETURN.
    ENDIF.
    IF substring( val = iv_token len = 3 ) <> `K1|`.
      RETURN.
    ENDIF.
    lv_body = substring( val = iv_token off = 3 ).
    rt_parts = decode_row( lv_body ).
  ENDMETHOD.
ENDCLASS.

CLASS lcl_plaidcl_stage DEFINITION FINAL.
  PUBLIC SECTION.
    " PC_ + 19 hex digits of GENERATE_SEC_RANDOM output = 22 characters,
    " the width of INDX-SRTFD. Initial when the random source fails.
    CLASS-METHODS new_token RETURNING VALUE(rv_token) TYPE string.
    " Exactly the new_token shape. Anything else (longer than 22, trailing
    " blanks, another prefix) would alias or reach a customer INDX record.
    CLASS-METHODS is_token IMPORTING iv_token TYPE string RETURNING VALUE(rv_ok) TYPE abap_bool.
    " Contract 3: text -> the four MESSAGE e001(00) WITH chunks.
    CLASS-METHODS msg_chunks
      IMPORTING iv_text TYPE string
      EXPORTING ev_v1   TYPE symsgv
                ev_v2   TYPE symsgv
                ev_v3   TYPE symsgv
                ev_v4   TYPE symsgv.
    " Stamps ZA-accessed now; B9 measures its TTL from this. Update-only:
    " a ctrl record B9 already reaped is never recreated (that left the
    " token NOT_READY forever). abap_false = the token is gone.
    CLASS-METHODS touch IMPORTING iv_token TYPE string RETURNING VALUE(rv_found) TYPE abap_bool.
    " Text of the message a CALL FUNCTION ... EXCEPTIONS error_message caught.
    CLASS-METHODS message_text RETURNING VALUE(rv_text) TYPE string.
ENDCLASS.

CLASS lcl_plaidcl_stage IMPLEMENTATION.
  METHOD new_token.
    DATA lv_random TYPE xstring.
    DATA lv_hex    TYPE string.
    CALL FUNCTION 'GENERATE_SEC_RANDOM'
      EXPORTING
        length         = 10
      IMPORTING
        random         = lv_random
      EXCEPTIONS
        invalid_length = 1
        no_memory      = 2
        internal_error = 3
        error_message  = 4
        OTHERS         = 5.
    IF sy-subrc <> 0 OR xstrlen( lv_random ) < 10.
      RETURN.
    ENDIF.
    lv_hex = |{ lv_random }|.
    rv_token = `PC_` && substring( val = lv_hex len = 19 ).
  ENDMETHOD.

  METHOD is_token.
    rv_ok = xsdbool( matches( val = iv_token regex = `PC_[0-9A-F]{19}` ) ).
  ENDMETHOD.

  METHOD msg_chunks.
    " MESSAGE ... WITH drops each variable's trailing blanks, so a chunk never
    " ends on a blank: the blanks open the next chunk, where they survive.
    DATA lv_rest  TYPE string.
    DATA lv_len   TYPE i.
    DATA lv_chunk TYPE symsgv.
    CLEAR: ev_v1, ev_v2, ev_v3, ev_v4.
    lv_rest = iv_text.
    DO 4 TIMES.
      DATA(lv_part) = sy-index.
      lv_len = nmin( val1 = strlen( lv_rest ) val2 = 50 ).
      WHILE lv_len > 1 AND lv_len < strlen( lv_rest ) AND substring( val = lv_rest off = lv_len - 1 len = 1 ) = ` `.
        lv_len = lv_len - 1.
      ENDWHILE.
      lv_chunk = substring( val = lv_rest len = lv_len ).
      CASE lv_part.
        WHEN 1. ev_v1 = lv_chunk.
        WHEN 2. ev_v2 = lv_chunk.
        WHEN 3. ev_v3 = lv_chunk.
        WHEN 4. ev_v4 = lv_chunk.
      ENDCASE.
      lv_rest = substring( val = lv_rest off = lv_len ).
    ENDDO.
  ENDMETHOD.

  METHOD touch.
    DATA ls_ctrl TYPE ty_plaidcl_stage_ctrl.
    DATA lv_id   TYPE indx-srtfd.
    lv_id = iv_token.
    IMPORT ctrl = ls_ctrl FROM DATABASE indx(za) ID lv_id.
    IF sy-subrc <> 0.
      RETURN.
    ENDIF.
    GET TIME STAMP FIELD ls_ctrl-accessed.
    EXPORT ctrl = ls_ctrl TO DATABASE indx(za) ID lv_id.
    rv_found = abap_true.
  ENDMETHOD.

  METHOD message_text.
    MESSAGE ID sy-msgid TYPE 'I' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO rv_text.
  ENDMETHOD.
ENDCLASS.

CLASS ltcl_plaidcl_top DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.
  PRIVATE SECTION.
    METHODS check_row
      IMPORTING iv_name TYPE string it_fields TYPE string_table iv_row TYPE string.
    METHODS check_bad_row
      IMPORTING iv_name TYPE string iv_row TYPE string.
    METHODS check_token
      IMPORTING iv_name TYPE string it_parts TYPE string_table iv_token TYPE string.
    METHODS check_bad_token
      IMPORTING iv_name TYPE string iv_token TYPE string.
    METHODS codec_round_trip FOR TESTING.
    METHODS codec_vectors FOR TESTING.
    METHODS new_tokens_distinct FOR TESTING.
    " msg_chunks, then MESSAGE e001(00) (text &1&2&3&4) as the FMs raise it:
    " each chunk loses its trailing blanks there.
    METHODS rejoin_chunks
      IMPORTING iv_text        TYPE string
      RETURNING VALUE(rv_text) TYPE string.
    METHODS chunks_keep_boundary_blanks FOR TESTING.
    METHODS chunks_short_text FOR TESTING.
    METHODS chunks_empty_text FOR TESTING.
    METHODS chunks_long_blank_run FOR TESTING.
ENDCLASS.

CLASS ltcl_plaidcl_top IMPLEMENTATION.
  METHOD check_row.
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>encode_row( it_fields ) exp = iv_row
      msg = |encode_row vector { iv_name }| ).
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>decode_row( iv_row ) exp = it_fields
      msg = |decode_row vector { iv_name }| ).
  ENDMETHOD.

  METHOD check_bad_row.
    DATA lt_empty TYPE string_table.
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>decode_row( iv_row ) exp = lt_empty
      msg = |decode_row vector { iv_name } must decode to an initial table| ).
  ENDMETHOD.

  METHOD check_token.
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>encode_token( it_parts ) exp = iv_token
      msg = |encode_token vector { iv_name }| ).
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>decode_token( iv_token ) exp = it_parts
      msg = |decode_token vector { iv_name }| ).
  ENDMETHOD.

  METHOD check_bad_token.
    DATA lt_empty TYPE string_table.
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>decode_token( iv_token ) exp = lt_empty
      msg = |decode_token vector { iv_name } must decode to an initial table| ).
  ENDMETHOD.

  METHOD codec_round_trip.
    DATA lt_values TYPE string_table.
    DATA lv_cr     TYPE string.
    lv_cr = substring( val = cl_abap_char_utilities=>cr_lf len = 1 ).

    APPEND `back\slash` TO lt_values.
    APPEND `pi|pe` TO lt_values.
    APPEND `line` && cl_abap_char_utilities=>newline && `feed` TO lt_values.
    APPEND `carriage` && lv_cr && `return` TO lt_values.
    APPEND `tab` && cl_abap_char_utilities=>horizontal_tab && `stop` TO lt_values.
    APPEND `nul` && cl_abap_char_utilities=>minchar && `char` TO lt_values.
    APPEND `` TO lt_values.
    APPEND `\n` TO lt_values.
    APPEND `\` TO lt_values.
    APPEND `|` TO lt_values.
    APPEND `` TO lt_values.

    DATA(lv_line) = lcl_plaidcl_codec=>encode_row( lt_values ).

    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_codec=>decode_row( lv_line ) exp = lt_values
      msg = 'decode_row( encode_row( x ) ) must equal x, trailing empty field included' ).
    cl_abap_unit_assert=>assert_equals( act = find( val = lv_line sub = cl_abap_char_utilities=>newline ) exp = -1
      msg = 'encoded line must not contain LF' ).
    cl_abap_unit_assert=>assert_equals( act = find( val = lv_line sub = lv_cr ) exp = -1
      msg = 'encoded line must not contain CR' ).
    cl_abap_unit_assert=>assert_equals( act = find( val = lv_line sub = cl_abap_char_utilities=>horizontal_tab ) exp = -1
      msg = 'encoded line must not contain TAB' ).
    cl_abap_unit_assert=>assert_equals( act = find( val = lv_line sub = cl_abap_char_utilities=>minchar ) exp = -1
      msg = 'encoded line must not contain U+0000' ).
  ENDMETHOD.

  " Mirrors test/codec_vectors.json vector for vector, in file order. Change
  " both together: the plaid/plaidlink codecs assert the same file.
  METHOD codec_vectors.
    DATA lt_list TYPE string_table.
    DATA lv_cr   TYPE string.
    DATA lv_ctl  TYPE string.
    lv_cr = substring( val = cl_abap_char_utilities=>cr_lf len = 1 ).

    CLEAR lt_list.
    APPEND `MARA` TO lt_list.
    APPEND `100` TO lt_list.
    APPEND `EUR` TO lt_list.
    check_row( iv_name = `plain` it_fields = lt_list iv_row = `MARA|100|EUR` ).
    CLEAR lt_list.
    APPEND `a\b` TO lt_list.
    check_row( iv_name = `backslash` it_fields = lt_list iv_row = `a\\b` ).
    CLEAR lt_list.
    APPEND `a|b` TO lt_list.
    check_row( iv_name = `pipe` it_fields = lt_list iv_row = `a\|b` ).
    CLEAR lt_list.
    APPEND `line1` && cl_abap_char_utilities=>newline && `line2` TO lt_list.
    check_row( iv_name = `lf` it_fields = lt_list iv_row = `line1\nline2` ).
    CLEAR lt_list.
    APPEND `a` && lv_cr && `b` TO lt_list.
    check_row( iv_name = `cr` it_fields = lt_list iv_row = `a\rb` ).
    CLEAR lt_list.
    APPEND `a` && cl_abap_char_utilities=>horizontal_tab && `b` TO lt_list.
    check_row( iv_name = `tab` it_fields = lt_list iv_row = `a\tb` ).
    CLEAR lt_list.
    APPEND `a` && cl_abap_char_utilities=>minchar && `b` TO lt_list.
    check_row( iv_name = `nul` it_fields = lt_list iv_row = `a\0b` ).
    CLEAR lt_list.
    APPEND `\|` && cl_abap_char_utilities=>newline && lv_cr && cl_abap_char_utilities=>horizontal_tab && cl_abap_char_utilities=>minchar TO lt_list.
    check_row( iv_name = `all_escapes_in_one_field` it_fields = lt_list iv_row = `\\\|\n\r\t\0` ).
    CLEAR lt_list.
    APPEND `\n` TO lt_list.
    APPEND `\0` TO lt_list.
    check_row( iv_name = `escape_lookalike` it_fields = lt_list iv_row = `\\n|\\0` ).
    CLEAR lt_list.
    APPEND `a` TO lt_list.
    APPEND `` TO lt_list.
    APPEND `b` TO lt_list.
    check_row( iv_name = `empty_middle_field` it_fields = lt_list iv_row = `a||b` ).
    CLEAR lt_list.
    APPEND `a` TO lt_list.
    APPEND `` TO lt_list.
    check_row( iv_name = `trailing_empty_field` it_fields = lt_list iv_row = `a|` ).
    CLEAR lt_list.
    APPEND `` TO lt_list.
    APPEND `` TO lt_list.
    APPEND `` TO lt_list.
    check_row( iv_name = `all_empty_fields` it_fields = lt_list iv_row = `||` ).
    CLEAR lt_list.
    APPEND `` TO lt_list.
    check_row( iv_name = `single_empty_field` it_fields = lt_list iv_row = `` ).
    CLEAR lt_list.
    APPEND `\` TO lt_list.
    check_row( iv_name = `lone_backslash` it_fields = lt_list iv_row = `\\` ).
    CLEAR lt_list.
    APPEND `abc\` TO lt_list.
    APPEND `d` TO lt_list.
    check_row( iv_name = `ends_with_backslash` it_fields = lt_list iv_row = `abc\\|d` ).
    CLEAR lt_list.
    APPEND `|` TO lt_list.
    check_row( iv_name = `just_pipe` it_fields = lt_list iv_row = `\|` ).
    CLEAR lt_list.
    APPEND `|` TO lt_list.
    APPEND `` TO lt_list.
    check_row( iv_name = `pipe_then_empty` it_fields = lt_list iv_row = `\||` ).
    CLEAR lt_list.
    APPEND `Müller` TO lt_list.
    APPEND `東京` TO lt_list.
    APPEND `€5` TO lt_list.
    check_row( iv_name = `multibyte` it_fields = lt_list iv_row = `Müller|東京|€5` ).
    CLEAR lt_list.
    APPEND ` a ` TO lt_list.
    APPEND ` ` TO lt_list.
    check_row( iv_name = `spaces_preserved` it_fields = lt_list iv_row = ` a | ` ).
    CLEAR lt_list.
    lv_ctl = `a` && cl_abap_conv_in_ce=>uccp( '0001' ) && `b` && cl_abap_conv_in_ce=>uccp( '001F' ) && `c`.
    APPEND lv_ctl TO lt_list.
    check_row( iv_name = `control_char_passthrough` it_fields = lt_list iv_row = lv_ctl ).
    check_bad_row( iv_name = `dangling_escape` iv_row = `abc\` ).
    check_bad_row( iv_name = `unknown_escape` iv_row = `a\xb` ).
    check_bad_row( iv_name = `escaped_n_uppercase` iv_row = `a\N` ).
    CLEAR lt_list.
    APPEND `MARA` TO lt_list.
    APPEND `2` TO lt_list.
    APPEND `100|A` TO lt_list.
    check_token( iv_name = `token_keyset_three_parts` it_parts = lt_list iv_token = `K1|MARA|2|100\|A` ).
    CLEAR lt_list.
    APPEND `DD03L` TO lt_list.
    APPEND `` TO lt_list.
    check_token( iv_name = `token_trailing_empty_part` it_parts = lt_list iv_token = `K1|DD03L|` ).
    CLEAR lt_list.
    APPEND `` TO lt_list.
    check_token( iv_name = `token_single_empty_part` it_parts = lt_list iv_token = `K1|` ).
    CLEAR lt_list.
    APPEND `a\b` TO lt_list.
    APPEND `x` && cl_abap_char_utilities=>newline && `y` TO lt_list.
    check_token( iv_name = `token_escaped_parts` it_parts = lt_list iv_token = `K1|a\\b|x\ny` ).
    check_bad_token( iv_name = `token_empty` iv_token = `` ).
    check_bad_token( iv_name = `token_too_short` iv_token = `K1` ).
    check_bad_token( iv_name = `token_wrong_version` iv_token = `K2|MARA` ).
    check_bad_token( iv_name = `token_lowercase_prefix` iv_token = `k1|MARA` ).
    check_bad_token( iv_name = `token_no_prefix` iv_token = `MARA|1` ).
    check_bad_token( iv_name = `token_dangling_escape` iv_token = `K1|MARA\` ).
    check_bad_token( iv_name = `token_unknown_escape` iv_token = `K1|a\x` ).
  ENDMETHOD.

  METHOD new_tokens_distinct.
    DATA lt_tokens TYPE string_table.
    DATA lv_token  TYPE string.

    DO 1000 TIMES.
      lv_token = lcl_plaidcl_stage=>new_token( ).
      cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_stage=>is_token( lv_token ) exp = abap_true
        msg = |new_token must produce PC_ + 19 hex, got [{ lv_token }]| ).
      APPEND lv_token TO lt_tokens.
    ENDDO.
    SORT lt_tokens.
    DELETE ADJACENT DUPLICATES FROM lt_tokens.
    cl_abap_unit_assert=>assert_equals( act = lines( lt_tokens ) exp = 1000
      msg = '1000 generated tokens must all be distinct' ).

    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_stage=>is_token( lv_token && `0` ) exp = abap_false
      msg = 'a 23-character token must be refused' ).
    cl_abap_unit_assert=>assert_equals( act = lcl_plaidcl_stage=>is_token( `ZZCUSTOMER` ) exp = abap_false
      msg = 'a non-PC_ id must be refused' ).
  ENDMETHOD.

  METHOD rejoin_chunks.
    DATA lv_v1 TYPE symsgv.
    DATA lv_v2 TYPE symsgv.
    DATA lv_v3 TYPE symsgv.
    DATA lv_v4 TYPE symsgv.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = iv_text
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    MESSAGE e001(00) WITH lv_v1 lv_v2 lv_v3 lv_v4 INTO rv_text.
  ENDMETHOD.

  METHOD chunks_keep_boundary_blanks.
    " Blanks at positions 50 and 100: a chunker cutting every 50 characters
    " ends chunks 1 and 2 on them, and MESSAGE drops both.
    DATA(lv_text) = |{ repeat( val = `A` occ = 49 ) } { repeat( val = `B` occ = 49 ) } { repeat( val = `C` occ = 20 ) }|.
    cl_abap_unit_assert=>assert_equals( act = strlen( lv_text ) exp = 120 msg = 'test setup: text length' ).
    cl_abap_unit_assert=>assert_equals( act = rejoin_chunks( lv_text ) exp = lv_text
                                        msg = 'blanks at 50/100-character boundaries were lost' ).
  ENDMETHOD.

  METHOD chunks_short_text.
    DATA lv_v1 TYPE symsgv.
    DATA lv_v2 TYPE symsgv.
    DATA lv_v3 TYPE symsgv.
    DATA lv_v4 TYPE symsgv.
    DATA(lv_text) = ` Table SPFLI: not authorized`.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = lv_text
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    cl_abap_unit_assert=>assert_equals( act = |{ lv_v1 }| exp = lv_text msg = 'short text must be chunk 1 whole' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v2 msg = 'chunk 2' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v3 msg = 'chunk 3' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v4 msg = 'chunk 4' ).
    cl_abap_unit_assert=>assert_equals( act = rejoin_chunks( lv_text ) exp = lv_text msg = 'short text rejoined' ).
  ENDMETHOD.

  METHOD chunks_empty_text.
    DATA lv_v1 TYPE symsgv VALUE 'stale'.
    DATA lv_v2 TYPE symsgv VALUE 'stale'.
    DATA lv_v3 TYPE symsgv VALUE 'stale'.
    DATA lv_v4 TYPE symsgv VALUE 'stale'.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = ``
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    cl_abap_unit_assert=>assert_initial( act = lv_v1 msg = 'chunk 1' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v2 msg = 'chunk 2' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v3 msg = 'chunk 3' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v4 msg = 'chunk 4' ).
    cl_abap_unit_assert=>assert_initial( act = rejoin_chunks( `` ) msg = 'empty text rejoined' ).
  ENDMETHOD.

  METHOD chunks_long_blank_run.
    " Pins a known limit. A blank run that fills a whole chunk cannot be
    " carried: a chunk of blanks is empty after MESSAGE. msg_chunks then
    " spends one blank per remaining chunk and the text after the run is
    " lost. A cut-every-50 chunker would deliver the X in chunk 3 instead.
    DATA lv_v1 TYPE symsgv.
    DATA lv_v2 TYPE symsgv.
    DATA lv_v3 TYPE symsgv.
    DATA lv_v4 TYPE symsgv.
    DATA(lv_head) = repeat( val = `A` occ = 49 ).
    DATA(lv_text) = |{ lv_head }{ repeat( val = ` ` occ = 60 ) }X|.
    lcl_plaidcl_stage=>msg_chunks( EXPORTING iv_text = lv_text
                                   IMPORTING ev_v1 = lv_v1 ev_v2 = lv_v2 ev_v3 = lv_v3 ev_v4 = lv_v4 ).
    cl_abap_unit_assert=>assert_equals( act = |{ lv_v1 }| exp = lv_head msg = 'chunk 1' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v2 msg = 'chunk 2' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v3 msg = 'chunk 3' ).
    cl_abap_unit_assert=>assert_initial( act = lv_v4 msg = 'chunk 4' ).
    cl_abap_unit_assert=>assert_equals( act = rejoin_chunks( lv_text ) exp = lv_head msg = 'rejoined text' ).
  ENDMETHOD.
ENDCLASS.