*&---------------------------------------------------------------------*
*& sc-28323 (B2S -- Z_PLAIDCL_B2_SEARCH, RFC wrapper).
*&---------------------------------------------------------------------*
* SERVER-SIDE search over the SAP table catalog: SELECT TABNAME LIKE
* <pattern> FROM DD02L, optionally cross-filtered against DD02T-DDTEXT,
* bounded by IV_MAX_HITS -- NEVER enumerate-then-rank. A production ECC
* carries tens of thousands of DD02L rows; materialising that catalog
* client-side to search it locally is wrong at any cap, which is the
* whole reason this FM exists instead of a wider IV_MAX_ENTRIES on B2's
* own classify_batch. This closes sc-27751 Track B's biggest remaining
* product gap: a user could already VERIFY a table name (B2) but could
* not BROWSE or DISCOVER one at all.
*
* DIRECT REUSE, NOT A COPY: every other Bn wrapper in this package that
* wraps a REPORT's proven logic copies it under a fresh local-class
* prefix, because a REPORT and this FUGR are separate ABAP compile
* units. That constraint does NOT apply here -- LCL_B2_TABLE_CATALOG
* (z_plaidcl_b2_cattable_fm.abap) is itself an FM already living in
* THIS SAME Z_PLAIDCL function group, and every FM in a group compiles
* as one unit (B1's own header says so explicitly). Two precedents
* already prove cross-FM-file local-class calls work live in this
* exact group: Z_PLAIDCL_B2_CATTABLE's own classify_batch calls B5's
* PUBLIC LCL_B5_SQL=>CHECK_IDENTIFIER directly
* (z_plaidcl_b2_cattable_fm.abap), and Z_PLAIDCL_B12_RUN_ASYNC calls
* B7's PUBLIC LCL_B7_TCODE_CAPTURE=>DECODE_SELECTION directly
* (z_plaidcl_b12_run_async.abap). This file follows that SAME
* established pattern: it calls LCL_B2_TABLE_CATALOG=>CLASSIFY_TABLE
* directly, verbatim, unmodified -- the strongest possible form of
* "reusing that logic, not changing its behaviour", since it is
* literally the same compiled method, not a fork that could drift.
* LCL_B5_SQL (B5) is reused the same way, for the same reason.
*
* Deploys into the SAME Z_PLAIDCL function group as B1/B2/B3/B4/B5/B6/
* B7/B8/B12. New names introduced here: LCL_B2S_TABLE_SEARCH (class,
* "b2s" prefix for group-scope hygiene, matching every other wrapper's
* convention) -- no local class/type name colliding with those owned
* by B1/B2/B3/B4/B5/B6/B7/B8/B12 in the group (checked against every
* file's own header before writing this one).
*
* SEARCH SEMANTICS: IV_NAME_PATTERN uses '*' as a multi-char wildcard
* (translated to SQL LIKE '%', with the caller's own literal '%'/'_'/
* '#' escaped first via an ESCAPE '#' clause so they can never be
* mistaken for wildcards or break the escape scheme) and is matched
* against DD02L-TABNAME. IV_DESC_PATTERN, if given, is matched against
* DD02T-DDTEXT using ABAP's native CP operator (its OWN '*'/'+'
* wildcard syntax) IN MEMORY, case-insensitively, over the candidate
* set IV_NAME_PATTERN already produced -- never a second independent
* DD02T-wide LIKE scan. See "TRUNCATION HONESTY" below for exactly
* what that composition does and does not guarantee.
*
* LEADING-WILDCARD SCAN COST (requirement: note what we do about it).
* DD02L is keyed MANDT+TABNAME, so a NON-leading-wildcard pattern (no
* '*' as the first character) drives a genuine indexed prefix range
* scan. A LEADING-wildcard pattern (e.g. "*SALES*") defeats that index
* by construction -- no ABAP-side trick changes that, the database has
* no secondary index on a reversed/suffixed TABNAME. This code does
* NOT special-case that shape differently; it issues the identical
* RFC_READ_TABLE call either way, but ALWAYS bounds it with
* ROWCOUNT = IV_MAX_HITS + 1 (the "+1" is how EV_TRUNCATED below is
* derived). That is the one honest mitigation available at this layer:
* we cannot add a database index from an RFC call, so we bound the
* fetch instead of letting a non-selective leading-wildcard pattern
* run unbounded. A leading-wildcard search against a genuinely huge
* DD02L is therefore still a real, if bounded, table scan -- said
* plainly rather than hidden behind a fast-looking API.
*&---------------------------------------------------------------------*
* TRUNCATION HONESTY (requirement: never let a caller think they saw
* everything). EV_TRUNCATED reflects the NAME-LEVEL (+ TABCLASS-filter)
* match space only: the DD02L fetch itself is bounded at
* IV_MAX_HITS + 1 rows. If that raw fetch returns MORE than
* IV_MAX_HITS rows, EV_TRUNCATED = 'X' and only the first IV_MAX_HITS
* are processed further -- the SAME "silently truncated is the same
* defect class as RFC_READ_TABLE's C(72) truncation" property this
* whole package exists to avoid, made explicit instead of hidden.
* When EV_TRUNCATED = ' ' (false), the name+tabclass match space was
* seen IN FULL, so if IV_DESC_PATTERN was also given, the returned
* hits are the exact, complete answer for BOTH filters combined. When
* EV_TRUNCATED = 'X' (true), only a bounded PREFIX of the name matches
* was examined before any description filtering -- the true combined-
* filter total is UNKNOWN and may be higher than what is returned;
* that is the honest caveat, not a bug to paper over.
*
* CLASSIFICATION HONESTY (requirement: NOT_OFFERABLE hits stay in the
* result, with a reason, never silently dropped). Every hit carries
* EV_CLASSIFY exactly as LCL_B2_TABLE_CATALOG produces it -- one of
* CURSOR_NATIVE / PRIMARY_KEY_ONLY / NOT_OFFERABLE, never filtered and
* never coerced to a boolean. REASON is populated only for a
* NOT_OFFERABLE hit (derive_reason, new orchestration logic added by
* this file, not part of B2's proven method -- it just reads the
* ALREADY-computed TABCLASS/CLASSIFY/FOUND/RANK_NOTE fields B2 already
* returns and turns them into a human sentence, it does not re-decide
* anything B2 already decided).
*
* DESCRIPTION-ABSENT vs. DESCRIPTION-EMPTY (requirement: distinguish
* them). DESC_FOUND is a real ABAP_BOOL: 'X' iff a DD02T row exists for
* (TABNAME, the resolved language); DESCRIPTION is that row's raw
* DDTEXT verbatim, which can itself legitimately be blank even when
* DESC_FOUND = 'X'. No language fallback is attempted if the requested
* language has no DD02T row -- same "never guessed" convention as B2's
* own STALE_NO_DD09L_FALLBACK.
*
* WIRE CONTRACT:
*   - Every ABAP_BOOL field (EV_TRUNCATED, DESC_FOUND-per-row) crosses
*     RFC as 'X' / a single space, never blank -- compare explicitly
*     (`value == 'X'`), same caveat as every other Bn FM in this
*     package (a bare space is truthy Python).
*   - ET_HITS rows are CODEC rows (lcl_plaidcl_codec=>encode_row /
*     decode_row, Contract 2), exactly 6 fields in this fixed order:
*       "TABNAME|TABCLASS|CLASSIFY|DESC_FOUND|REASON|DESCRIPTION"
*     DESCRIPTION is raw, user-authored DD02T-DDTEXT and can contain a
*     pipe or a backslash (REASON stays a fixed template phrase plus a
*     DDIC TABCLASS token, never free text, but is encoded the same way
*     for uniformity). A caller MUST decode with the codec, never a
*     plain `split('|')`: decoding always recovers exactly 6 fields
*     regardless of what DESCRIPTION contains.
*   - IV_MAX_HITS default 100, hard ceiling 1000 (C_HARD_CEILING) --
*     IV_MAX_HITS outside [1, 1000] is INVALID_INPUT. IV_NAME_PATTERN
*     longer than 30 raw characters is also INVALID_INPUT (DD02L-
*     TABNAME is at most 16 characters; 30 is a generous cap on the
*     wildcarded SEARCH PATTERN, matching this package's own
*     "identifiers <= 30 chars" convention, chosen so the escaped LIKE
*     text can never approach the RFC_DB_OPT-TEXT C(72) bound -- an
*     internal check on the fully-built WHERE text enforces that bound
*     explicitly too, and refuses rather than silently truncating in
*     the pathological case an all-escaped-character pattern could
*     still reach it).
*
* GUARD (requirement: refuse a match-everything pattern rather than
* quietly returning the first N of everything, which would recreate
* the enumeration this FM was explicitly built to avoid). IV_NAME_
* PATTERN must contain at least one non-'*' character after stripping
* wildcards; blank or all-'*' is INVALID_INPUT. IV_DESC_PATTERN has no
* such guard -- it is optional and narrows an ALREADY name-bounded
* set, so an all-wildcard (or blank) value is a legitimate no-op
* meaning "no description filter", not a path back to full enumeration.
*
* SCOPE: target is SAP_BASIS 816 ABAP Platform, no S4CORE. DD02L/DD02T
* are DDIC catalog metadata, genuinely populous here (DD02L carries
* thousands of rows on this trial system) -- unlike ERP business
* tables, this surface is real and testable on THIS system, not just
* logic-reviewed.
*&---------------------------------------------------------------------*

CLASS lcl_b2s_table_search DEFINITION FINAL.
  PUBLIC SECTION.
    CONSTANTS c_delimiter       TYPE c LENGTH 1 VALUE '|'.
    CONSTANTS c_hard_ceiling    TYPE i VALUE 1000.   " IV_MAX_HITS ceiling
    CONSTANTS c_max_pattern_len TYPE i VALUE 30.      " IV_NAME_PATTERN raw length cap
    CONSTANTS c_max_desc_len    TYPE i VALUE 60.      " IV_DESC_PATTERN raw length cap (DD02T-DDTEXT is CHAR60)
    CONSTANTS c_max_where_len   TYPE i VALUE 72.      " RFC_DB_OPT-TEXT hard bound (see file header)

    " Translates the caller's '*'-wildcard NAME pattern into a safe SQL
    " LIKE fragment: any literal quote/'%'/'_'/'#' in the caller's text
    " is escaped FIRST (quotes doubled), '#' doubled and '%'/'_'
    " '#'-escaped so they read as literal, ONLY THEN is the caller's
    " '*' translated to SQL '%'. EV_HAS_LITERAL is false when nothing
    " but wildcards survives stripping -- the FM body turns that into
    " the match-everything refusal (see file header GUARD).
    CLASS-METHODS build_like_pattern
      IMPORTING pv_raw_pattern  TYPE string
      EXPORTING ev_like         TYPE string
                ev_has_literal  TYPE abap_bool.

    " '*' (any TABCLASS) or a value that passes B5's own
    " LCL_B5_SQL=>CHECK_IDENTIFIER -- wrapped in TRY/CATCH HERE
    " (a local class method), never in the FM body itself, per this
    " group's own hard rule that a classic-EXCEPTIONS FM cannot use
    " TRY/CATCH in its top-level body.
    CLASS-METHODS validate_tabclass_filter
      IMPORTING pv_value        TYPE string
      RETURNING VALUE(rv_valid) TYPE abap_bool.

    " One DD02T lookup for one already-known-valid TABNAME (sourced
    " from a prior DD02L read, so it is DB-known-good and safe to
    " embed directly -- the SAME trust model B2's own CLASSIFY_TABLE
    " already uses for PV_TABNAME). EV_FOUND distinguishes "no DD02T
    " row for this language" from "row present, DDTEXT blank".
    CLASS-METHODS fetch_description
      IMPORTING pv_tabname      TYPE string
                pv_langu        TYPE string
      EXPORTING ev_found        TYPE abap_bool
                ev_description  TYPE string.

    " NEW logic (not part of B2's proven method): turns the ALREADY-
    " computed classification fields B2 returns into a human-readable
    " reason, populated only when CLASSIFY = NOT_OFFERABLE. Re-reads
    " B2's own decision, never re-decides it.
    CLASS-METHODS derive_reason
      IMPORTING ps_result          TYPE ty_b2_classification
      RETURNING VALUE(rv_reason)   TYPE string.

    " ORCHESTRATION: bounded DD02L LIKE scan -> optional per-hit DD02T
    " description fetch + in-memory CP filter -> per-hit classification
    " via B2's own LCL_B2_TABLE_CATALOG=>CLASSIFY_TABLE (direct reuse,
    " see file header) -> flattened wire rows.
    CLASS-METHODS search
      IMPORTING pv_name_like       TYPE string
                pv_desc_pattern    TYPE string
                pv_tabclass_filter TYPE string
                pv_langu           TYPE string
                pv_max_hits        TYPE i
      EXPORTING ev_truncated       TYPE abap_bool
                et_rows            TYPE string_table.
ENDCLASS.

CLASS lcl_b2s_table_search IMPLEMENTATION.

  METHOD build_like_pattern.
    DATA(lv_upper) = to_upper( pv_raw_pattern ).
    CONDENSE lv_upper.

    " literal-content check: strip '*' and see if anything real remains
    DATA(lv_literal_only) = lv_upper.
    REPLACE ALL OCCURRENCES OF '*' IN lv_literal_only WITH ''.
    ev_has_literal = xsdbool( lv_literal_only IS NOT INITIAL ).

    " 1) SQL literal-quote safety first: double embedded quotes.
    DATA(lv_esc) = replace( val = lv_upper sub = `'` with = `''` occ = 0 ).

    " 2) escape our OWN escape char, then the two SQL LIKE metachars,
    "    so a caller's literal '%'/'_'/'#' can never be mistaken for a
    "    wildcard or corrupt the escape scheme. Order matters: '#'
    "    must be doubled BEFORE '%'/'_' are '#'-prefixed, or a
    "    caller's own '#' would collide with an escape we just added.
    REPLACE ALL OCCURRENCES OF '#' IN lv_esc WITH '##'.
    REPLACE ALL OCCURRENCES OF '%' IN lv_esc WITH '#%'.
    REPLACE ALL OCCURRENCES OF '_' IN lv_esc WITH '#_'.

    " 3) ONLY NOW translate the caller's own wildcard syntax.
    REPLACE ALL OCCURRENCES OF '*' IN lv_esc WITH '%'.

    ev_like = lv_esc.
  ENDMETHOD.

  METHOD validate_tabclass_filter.
    IF pv_value = '*'.
      rv_valid = abap_true.
      RETURN.
    ENDIF.
    TRY.
        lcl_b5_sql=>check_identifier( iv_name = pv_value iv_code = `INVALID_INPUT` ).
        rv_valid = abap_true.
      CATCH lcx_b5.
        rv_valid = abap_false.
    ENDTRY.
  ENDMETHOD.

  METHOD fetch_description.
    CLEAR: ev_found, ev_description.

    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.

    APPEND VALUE #( fieldname = 'DDTEXT' ) TO lt_fields.
    APPEND VALUE #( text = |TABNAME = '{ pv_tabname }' AND DDLANGUAGE = '{ pv_langu }'| ) TO lt_options.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD02T' delimiter = '|' rowcount = 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    IF sy-subrc = 0 AND lines( lt_data ) > 0.
      ev_found       = abap_true.
      ev_description = lt_data[ 1 ]-wa.
    ENDIF.
  ENDMETHOD.

  METHOD derive_reason.
    IF ps_result-classify <> 'NOT_OFFERABLE'.
      RETURN.   " offerable hit -- no reason needed, wire field stays blank
    ENDIF.

    IF ps_result-found = abap_false.
      rv_reason = ps_result-rank_note.   " "no DD02L entry found" -- already descriptive
      RETURN.
    ENDIF.

    rv_reason = COND string(
      WHEN ps_result-tabclass = 'VIEW'
        THEN 'VIEW with no key field in DD03L -- not extractable via keyset paging'
      WHEN ps_result-tabclass = 'INTTAB'
        THEN 'INTTAB -- structure/internal table, no physical DB storage'
      ELSE |unrecognized TABCLASS [{ ps_result-tabclass }] -- refusing rather than guessing| ).
  ENDMETHOD.

  METHOD search.
    CLEAR: ev_truncated, et_rows.

    DATA lt_fields  TYPE STANDARD TABLE OF rfc_db_fld.
    DATA lt_options TYPE STANDARD TABLE OF rfc_db_opt.
    DATA lt_data    TYPE STANDARD TABLE OF tab512.

    APPEND VALUE #( fieldname = 'TABNAME' )  TO lt_fields.
    APPEND VALUE #( fieldname = 'TABCLASS' ) TO lt_fields.
    APPEND VALUE #( text = |TABNAME LIKE '{ pv_name_like }' ESCAPE '#'| ) TO lt_options.
    IF pv_tabclass_filter <> '*'.
      APPEND VALUE #( text = |AND TABCLASS = '{ pv_tabclass_filter }'| ) TO lt_options.
    ENDIF.

    " Bound the fetch at MAX_HITS + 1 -- see file header "LEADING-
    " WILDCARD SCAN COST" and "TRUNCATION HONESTY". This is the ONLY
    " mitigation available at this layer for a leading-wildcard
    " pattern that defeats DD02L's TABNAME index.
    CALL FUNCTION 'RFC_READ_TABLE'
      EXPORTING query_table = 'DD02L' delimiter = '|' rowcount = pv_max_hits + 1
      TABLES options = lt_options fields = lt_fields data = lt_data
      EXCEPTIONS OTHERS = 7.
    IF sy-subrc <> 0.
      RETURN.   " genuine RFC/DB failure -- an honest empty result, never a fabricated hit
    ENDIF.

    IF lines( lt_data ) > pv_max_hits.
      ev_truncated = abap_true.
    ENDIF.

    DATA(lv_kept) = 0.
    LOOP AT lt_data INTO DATA(ls_row).
      IF lv_kept >= pv_max_hits.
        EXIT.
      ENDIF.

      SPLIT ls_row-wa AT '|' INTO TABLE DATA(lt_parts).
      DATA(lv_tabname) = COND string( WHEN lines( lt_parts ) >= 1 THEN lt_parts[ 1 ] ELSE '' ).
      CONDENSE lv_tabname.
      IF lv_tabname IS INITIAL.
        CONTINUE.
      ENDIF.

      DATA lv_desc_found TYPE abap_bool.
      DATA lv_description TYPE string.
      fetch_description(
        EXPORTING pv_tabname     = lv_tabname
                  pv_langu       = pv_langu
        IMPORTING ev_found       = lv_desc_found
                  ev_description = lv_description ).

      IF pv_desc_pattern IS NOT INITIAL.
        " case-insensitive in-memory match, ABAP's OWN '*'/'+' wildcard
        " syntax (CP) -- no SQL involved, so no injection surface here
        " regardless of what the caller's description pattern contains.
        " CP's operands are kept as plain variables (not inlined
        " function calls) -- untested territory otherwise.
        DATA(lv_desc_upper) = to_upper( lv_description ).
        DATA(lv_desc_pat_upper) = to_upper( pv_desc_pattern ).
        IF lv_desc_found = abap_false OR NOT ( lv_desc_upper CP lv_desc_pat_upper ).
          CONTINUE.
        ENDIF.
      ENDIF.

      lv_kept = lv_kept + 1.

      " Direct reuse of B2's own proven method -- see file header.
      DATA(ls_class) = lcl_b2_table_catalog=>classify_table( CONV #( lv_tabname ) ).
      DATA(lv_reason) = derive_reason( ls_class ).

      APPEND lcl_plaidcl_codec=>encode_row( VALUE string_table(
        ( |{ ls_class-tabname }| )
        ( |{ ls_class-tabclass }| )
        ( |{ ls_class-classify }| )
        ( CONV string( lv_desc_found ) )
        ( |{ lv_reason }| )
        ( |{ lv_description }| ) ) ) TO et_rows.
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.

*&---------------------------------------------------------------------*
*& THE FUNCTION MODULE ITSELF.
*&
*& Remote-enabled (RFC). Deploys as Z_PLAIDCL_B2_SEARCH inside the live
*& Z_PLAIDCL function group. Signature is INLINE between the FUNCTION
*& name and the terminating period -- see z_plaidcl_ping.abap for why
*& the classic *" Local Interface: block is forbidden here.
*&---------------------------------------------------------------------*
FUNCTION Z_PLAIDCL_B2_SEARCH.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_NAME_PATTERN) TYPE  STRING
*"     VALUE(IV_DESC_PATTERN) TYPE  STRING DEFAULT ''
*"     VALUE(IV_LANGU) TYPE  STRING DEFAULT ''
*"     VALUE(IV_TABCLASS_FILTER) TYPE  STRING DEFAULT '*'
*"     VALUE(IV_MAX_HITS) TYPE  I DEFAULT 100
*"  EXPORTING
*"     VALUE(EV_DELIMITER) TYPE  STRING
*"     VALUE(EV_HIT_COUNT) TYPE  I
*"     VALUE(EV_TRUNCATED) TYPE  BOOLE_D
*"     VALUE(ET_HITS) TYPE  STRING_TABLE
*"  EXCEPTIONS
*"      INVALID_INPUT
*"----------------------------------------------------------------------



  CLEAR: ev_delimiter, ev_hit_count, ev_truncated, et_hits.
  ev_delimiter = lcl_b2s_table_search=>c_delimiter.

  IF iv_max_hits < 1 OR iv_max_hits > lcl_b2s_table_search=>c_hard_ceiling.
    MESSAGE e001(00) WITH 'IV_MAX_HITS must be between 1 and 1000' RAISING invalid_input.
  ENDIF.

  IF strlen( iv_name_pattern ) > lcl_b2s_table_search=>c_max_pattern_len.
    MESSAGE e001(00) WITH 'IV_NAME_PATTERN exceeds the 30-char limit' RAISING invalid_input.
  ENDIF.

  IF strlen( iv_desc_pattern ) > lcl_b2s_table_search=>c_max_desc_len.
    MESSAGE e001(00) WITH 'IV_DESC_PATTERN exceeds the 60-char limit' RAISING invalid_input.
  ENDIF.

  IF lcl_b2s_table_search=>validate_tabclass_filter( to_upper( iv_tabclass_filter ) ) = abap_false.
    MESSAGE e001(00) WITH 'IV_TABCLASS_FILTER is not * or a valid identifier' RAISING invalid_input.
  ENDIF.

  " Language: '' means sy-langu, else must be exactly one alnum char
  " (a real SAP language code) -- validated by construction, not by
  " escaping, since it is embedded directly into a WHERE literal.
  DATA lv_langu TYPE sy-langu.
  IF iv_langu IS INITIAL.
    lv_langu = sy-langu.
  ELSE.
    DATA(lv_langu_upper) = to_upper( iv_langu ).
    IF strlen( lv_langu_upper ) <> 1
       OR NOT ( lv_langu_upper CO 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' ).
      MESSAGE e001(00) WITH 'IV_LANGU must be exactly one alnum char' RAISING invalid_input.
    ENDIF.
    lv_langu = lv_langu_upper.
  ENDIF.

  DATA lv_like       TYPE string.
  DATA lv_has_literal TYPE abap_bool.
  lcl_b2s_table_search=>build_like_pattern(
    EXPORTING pv_raw_pattern = iv_name_pattern
    IMPORTING ev_like        = lv_like
              ev_has_literal = lv_has_literal ).
  IF lv_has_literal = abap_false.
    " GUARD: refuse a match-everything pattern, see file header
    MESSAGE e001(00) WITH 'IV_NAME_PATTERN must not be wildcard-only' RAISING invalid_input.
  ENDIF.

  " Defensive C(72) check on the fully-built WHERE text -- see file
  " header "WIRE CONTRACT". Refuse explicitly rather than ever risk a
  " silent RFC_DB_OPT-TEXT truncation, the exact defect class this
  " whole package exists to prevent.
  DATA(lv_where_check) = |TABNAME LIKE '{ lv_like }' ESCAPE '#'|.
  IF strlen( lv_where_check ) > lcl_b2s_table_search=>c_max_where_len.
    MESSAGE e001(00) WITH 'Escaped pattern exceeds RFC_DB_OPT 72-char bound' RAISING invalid_input.
  ENDIF.

  DATA lv_desc_pattern TYPE string.
  lv_desc_pattern = iv_desc_pattern.
  CONDENSE lv_desc_pattern.

  DATA lv_truncated TYPE abap_bool.
  DATA lt_hits TYPE string_table.
  lcl_b2s_table_search=>search(
    EXPORTING pv_name_like       = lv_like
              pv_desc_pattern    = lv_desc_pattern
              pv_tabclass_filter = to_upper( iv_tabclass_filter )
              pv_langu           = CONV string( lv_langu )
              pv_max_hits        = iv_max_hits
    IMPORTING ev_truncated       = lv_truncated
              et_rows            = lt_hits ).

  ev_truncated = lv_truncated.
  et_hits      = lt_hits.
  ev_hit_count = lines( et_hits ).

ENDFUNCTION.

*&---------------------------------------------------------------------*
*& VERIFICATION: see z_plaidcl_b2_search_verify.abap (REPORT, live
*& AUnit companion). RUN LIVE against this trial system (SAP_BASIS 816,
*& A4H client 001), all 8 methods, first pass, no fixes needed:
*&   A. IV_NAME_PATTERN='DD02*' -> 21 real hits, not truncated (cap 50).
*&      DD02L came back TABCLASS=TRANSP CLASSIFY=CURSOR_NATIVE, exactly
*&      as B2's own checklist predicts.
*&   B. Self-derived description search: DD02L's live DD02T-DDTEXT is
*&      "SAP Tables"; re-searching IV_NAME_PATTERN='DD02L' with
*&      IV_DESC_PATTERN='*SAP *' (a substring of what step 1 just
*&      learned) returned exactly 1 hit, DESC_FOUND=X, description
*&      "SAP Tables" verbatim.
*&   C. IV_NAME_PATTERN='DD*', IV_MAX_HITS=5 -> EV_TRUNCATED=X,
*&      EV_HIT_COUNT=5 exactly (the cap).
*&   D. IV_NAME_PATTERN='RFC_DB*' -> RFC_DB_FLD and RFC_DB_OPT both
*&      came back TABCLASS=INTTAB CLASSIFY=NOT_OFFERABLE, REASON=
*&      "INTTAB -- structure/internal table, no physical DB storage" --
*&      never dropped, reason attached.
*&   E-H. Blank pattern, wildcard-only pattern, IV_MAX_HITS=0,
*&      IV_MAX_HITS=1001, and an injection-shaped IV_TABCLASS_FILTER
*&      all raised INVALID_INPUT (subrc=1), no RFC_READ_TABLE call made.
*& Group-level check: B1/B2/B3/B4/B5/B6/B7 all GET 200 after this FM's
*& activation -- no collateral damage to the rest of the group.
*&
*& Deploy:
*&   source scripts/adt.sh; adt_init
*&   adt_deploy_fm Z_PLAIDCL Z_PLAIDCL_B2_SEARCH \
*&     src/z_plaidcl_b2_search_fm.abap "PlaidCloud B2 table search"
*&   Confirm put=200 AND activationExecuted="true" with ZERO messages.
*&   (Confirmed live: put=200, activationExecuted="true", zero messages
*&   about this object.)
*&---------------------------------------------------------------------*
