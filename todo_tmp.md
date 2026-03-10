# CLX Dashboard Settings Tab — Implementation Plan

**Date:** 2026-03-09
**Status:** Architecture Blueprint
**Target:** ratatui 0.30, crossterm 0.28, Rust edition 2024

---

## Summary

Add a fourth "Settings" tab to the CLX dashboard (`clx dashboard`) that allows viewing and editing all configuration from `~/.clx/config.yaml` directly in the TUI. The tab uses a two-panel layout (section list on the left, field list on the right), an inline popup for editing individual fields, and an atomic write-on-save pattern. No new external dependencies beyond what is already in `Cargo.toml`.

---

## 1. Patterns and Conventions Found

| Pattern | Location | Notes |
|---------|----------|-------|
| `DashboardTab` enum + `ALL` const array | `app.rs:6-26` | Tab registration, title, index. New variant added here. |
| `InputMode` enum (Normal/Filter) | `app.rs:28-32` | Extended with Settings-specific modes. |
| `App` struct flat fields per tab | `app.rs:34-50` | New settings fields appended. |
| `scroll_down/up/page_*` match on `current_tab` | `app.rs:89-213` | New Settings arm added to every match. |
| `handle_key_event` match on `input_mode` | `event.rs:35-73` | New InputMode arms dispatched here. |
| `ui/mod.rs` render dispatch | `ui/mod.rs:23-28` | New `DashboardTab::Settings` arm. |
| Status bar help text | `ui/mod.rs:52-90` | Extended with settings key hints. |
| `Paragraph` + `Wrap` for scrollable content | `ui/rules.rs` | Reference for left-panel list rendering. |
| `Table` + `TableState` for row selection | `ui/sessions.rs` | Reference for right-panel field table. |
| `Config::load()` / `serde_yml` | `clx-core/src/config.rs:555-574` | Load pattern to replicate. |
| Atomic write via temp file | (new, based on existing backup pattern in `install.rs:162-179`) | Write-then-rename for safe saves. |

**Key observation:** The existing `scroll_down/scroll_up` methods in `app.rs` use a `match self.current_tab` pattern. The Settings tab must add arms to all six match blocks in those methods, or (preferred) delegate Settings-specific scroll to a helper method called from `App::scroll_*`. The pattern from sessions/audit — `TableState` for row tracking — is directly reusable for the right-panel field list.

---

## 2. Architecture Decision

**Chosen approach: In-place TEA-lite with manual field state, no new crates.**

Rationale:
- The research recommends `ratatui-form`, but CLX has ~35 fields across 8 sections. The existing dashboard uses raw ratatui widgets throughout. Adding `ratatui-form` would be the only external ratatui widget crate and introduces a dependency that may diverge from ratatui 0.30.
- The existing `Table` + `TableState` pattern in sessions/audit is well understood by this codebase. A two-panel layout (left: section list, right: field rows) built with `Table` widgets is idiomatic here.
- A popup overlay for editing (using ratatui's `Clear` widget + centered `Rect`, available in 0.30) requires zero new dependencies.
- ~35 fields is well within the manual management threshold (the research notes `rat-widget` is better for 50+).
- Dirty state tracking via `original_config: Config` vs `editing_config: Config` comparison is simple and explicit.

**Trade-offs accepted:**
- More boilerplate than `ratatui-form`, but full control and zero dependency risk.
- Enum select fields (DefaultDecision, ContextPressureMode) require a small cycle-through-options implementation rather than a dropdown widget — this is trivial.
- `McpCommandTool` list editing (add/remove entries) is deferred to Phase 4 to keep the MVP focused.

---

## 3. Complete Field Inventory with Widget Types

### Section 1: Validator (`validator`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `enabled` | `bool` | Toggle (Space/Enter cycles true/false) | none | true |
| `layer1_enabled` | `bool` | Toggle | none | true |
| `layer1_timeout_ms` | `u64` | Number input | 100..=300000 | 30000 |
| `default_decision` | `DefaultDecision` | Cycle select (ask/allow/deny) | none | ask |
| `trust_mode` | `bool` | Toggle (warn on enable) | display warning | false |
| `auto_allow_reads` | `bool` | Toggle | none | true |

### Section 2: Context (`context`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `enabled` | `bool` | Toggle | none | true |
| `auto_snapshot` | `bool` | Toggle | none | true |
| `embedding_model` | `String` | Text input | non-empty | "qwen3-embedding:0.6b" |

### Section 3: Ollama (`ollama`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `host` | `String` | Text input | starts with http:// or https:// | "http://127.0.0.1:11434" |
| `model` | `String` | Text input | non-empty | "qwen3:1.7b" |
| `embedding_model` | `String` | Text input | non-empty | "qwen3-embedding:0.6b" |
| `embedding_dim` | `usize` | Number input | 1..=65536 | 1024 |
| `timeout_ms` | `u64` | Number input | 100..=600000 | 60000 |
| `max_retries` | `u32` | Number input | 0..=10 | 3 |
| `retry_delay_ms` | `u64` | Number input | 0..=60000 | 100 |
| `retry_backoff` | `f32` | Number input (1 decimal) | 1.0..=10.0 | 2.0 |

### Section 4: User Learning (`user_learning`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `enabled` | `bool` | Toggle | none | true |
| `auto_whitelist_threshold` | `u32` | Number input | 1..=100 | 3 |
| `auto_blacklist_threshold` | `u32` | Number input | 1..=100 | 2 |

### Section 5: Logging (`logging`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `level` | `String` | Cycle select (trace/debug/info/warn/error) | one of 5 values | "info" |
| `file` | `String` | Text input | non-empty | "~/.clx/logs/clx.log" |
| `max_size_mb` | `u32` | Number input | 1..=1000 | 10 |
| `max_files` | `u32` | Number input | 1..=100 | 5 |

### Section 6: Context Pressure (`context_pressure`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `mode` | `ContextPressureMode` | Cycle select (auto/notify/disabled) | none | auto |
| `context_window_size` | `i64` | Number input | 1000..=2000000 | 200000 |
| `threshold` | `f64` | Number input (2 decimal) | 0.1..=1.0 | 0.80 |

### Section 7: Session Recovery (`session_recovery`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `enabled` | `bool` | Toggle | none | true |
| `stale_hours` | `u32` | Number input | 1..=168 | 2 |

### Section 8: MCP Tools (`mcp_tools`)

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `enabled` | `bool` | Toggle | none | true |
| `default_decision` | `DefaultDecision` | Cycle select (ask/allow/deny) | none | allow |
| `command_tools` | `Vec<McpCommandTool>` | Read-only list (Phase 4: editable) | — | (4 defaults) |

**Total editable fields: 35 scalar + 1 list = 36**

---

## 4. State Design

### 4.1 New `DashboardTab` Variant

```rust
// app.rs — DashboardTab enum
pub enum DashboardTab {
    Sessions,
    AuditLog,
    Rules,
    Settings,  // NEW
}

impl DashboardTab {
    pub const ALL: [DashboardTab; 4] = [
        Self::Sessions,
        Self::AuditLog,
        Self::Rules,
        Self::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            // ...
            Self::Settings => "Settings",
        }
    }
}
```

### 4.2 New `InputMode` Variants

```rust
// app.rs — InputMode enum
pub enum InputMode {
    Normal,
    Filter,
    // New variants:
    SettingsNav,     // Navigating sections/fields (j/k moves, Enter edits)
    SettingsEdit,    // Editing a text/number field (popup open, typing)
}
```

`SettingsNav` is active whenever `current_tab == Settings` in Normal mode. Switching to Settings tab auto-transitions to `SettingsNav`. Leaving Settings tab resets to `Normal`.

### 4.3 New `App` Fields

```rust
// app.rs — App struct additions
pub struct App {
    // ... existing fields ...

    // Settings tab state
    pub settings_section_idx: usize,          // which section is selected (0..7)
    pub settings_field_idx: usize,            // which field row is selected within section
    pub settings_field_table_state: TableState, // ratatui TableState for field list
    pub settings_section_scroll: u16,         // scroll for section list (future-proof)
    pub settings_original_config: Option<Config>, // snapshot on tab entry
    pub settings_editing_config: Option<Config>,  // live edits
    pub settings_is_dirty: bool,              // original != editing
    pub settings_edit_buffer: String,         // text being typed in popup
    pub settings_edit_error: Option<String>,  // validation error message
    pub settings_save_result: Option<String>, // "Saved" / error shown after save
    pub settings_confirm_reset: bool,         // confirmation dialog for Reset
}
```

### 4.4 Section Registry (compile-time constant)

```rust
// dashboard/settings/sections.rs — new file
pub struct SectionDef {
    pub key: &'static str,    // yaml key, e.g. "validator"
    pub title: &'static str,  // display name, e.g. "Validator"
    pub field_count: usize,   // number of fields
}

pub const SECTIONS: &[SectionDef] = &[
    SectionDef { key: "validator",        title: "Validator",        field_count: 6 },
    SectionDef { key: "context",          title: "Context",          field_count: 3 },
    SectionDef { key: "ollama",           title: "Ollama",           field_count: 8 },
    SectionDef { key: "user_learning",    title: "User Learning",    field_count: 3 },
    SectionDef { key: "logging",          title: "Logging",          field_count: 4 },
    SectionDef { key: "context_pressure", title: "Context Pressure", field_count: 3 },
    SectionDef { key: "session_recovery", title: "Session Recovery", field_count: 2 },
    SectionDef { key: "mcp_tools",        title: "MCP Tools",        field_count: 3 },
];
```

### 4.5 Field Descriptor Type

```rust
// dashboard/settings/fields.rs — new file

pub enum FieldWidget {
    Toggle,
    TextInput { max_len: usize },
    NumberU64 { min: u64, max: u64 },
    NumberU32 { min: u32, max: u32 },
    NumberI64 { min: i64, max: i64 },
    NumberF64 { min: f64, max: f64, decimals: u8 },
    NumberF32 { min: f32, max: f32, decimals: u8 },
    NumberUsize { min: usize, max: usize },
    CycleSelect { options: &'static [&'static str] },
}

pub struct FieldDef {
    pub label: &'static str,
    pub description: &'static str,
    pub widget: FieldWidget,
    pub warn_on_enable: bool,   // for trust_mode
}
```

### 4.6 Config Value Extraction / Injection

```rust
// dashboard/settings/config_bridge.rs — new file

/// Extract the current string value of a field for display
pub fn get_field_value(config: &Config, section: usize, field: usize) -> String;

/// Apply an edited string value back to config, returns validation error if any
pub fn set_field_value(
    config: &mut Config,
    section: usize,
    field: usize,
    raw: &str,
) -> Result<(), String>;

/// Toggle a bool field
pub fn toggle_field(config: &mut Config, section: usize, field: usize);

/// Cycle an enum field to next option
pub fn cycle_field(config: &mut Config, section: usize, field: usize);
```

---

## 5. UI Layout

### 5.1 Overall Layout (Settings Tab)

```
┌─ CLX Dashboard ──────────────────────────────────────────────────┐
│  Sessions  │  Audit Log  │  Rules  │ [Settings]                  │
├──────────────────────────────────────────────────────────────────┤
│ ┌─ Sections ──────┐ ┌─ Fields ──────────────────────────────────┐│
│ │ > Validator     │ │  Field                Value       Default  ││
│ │   Context       │ │ ──────────────────────────────────────────││
│ │   Ollama        │ │ > enabled             true        true    ││
│ │   User Learning │ │   layer1_enabled      true        true    ││
│ │   Logging       │ │   layer1_timeout_ms   30000       30000   ││
│ │   Ctx Pressure  │ │   default_decision    ask         ask     ││
│ │   Sess Recovery │ │   trust_mode          false       false   ││
│ │   MCP Tools     │ │   auto_allow_reads    true        true    ││
│ └─────────────────┘ └──────────────────────────────────────────┘│
│ [s]Save  [R]Reset  [d]Defaults  [Esc]Cancel             dirty: * │
└──────────────────────────────────────────────────────────────────┘
```

Left panel: 22 columns wide. Right panel: remainder.
Split via `Layout::horizontal([Constraint::Length(22), Constraint::Min(40)])`.

### 5.2 Edit Popup

When `input_mode == SettingsEdit`, a centered popup overlays the settings panel:

```
              ┌─ Edit: layer1_timeout_ms ─────────────────┐
              │ Layer 1 validation timeout in milliseconds │
              │                                            │
              │  Value: [30000_                         ]  │
              │                                            │
              │  Range: 100 – 300000                       │
              │  Default: 30000                            │
              │                                            │
              │  [Enter] Confirm   [Esc] Cancel            │
              └────────────────────────────────────────────┘
```

For Toggle and CycleSelect fields: no popup. Edit happens in-place on Space/Enter.

### 5.3 Dirty Indicator

Modified fields rendered with `Style::fg(Color::Yellow)`. Tab title becomes `"Settings *"`. Status line shows `[s]Save` highlighted in yellow.

---

## 6. Key Binding Design

### 6.1 SettingsNav Mode

```
Key                  Action
───                  ──────
Tab / BackTab        Switch to next/prev tab
1/2/3/4              Direct tab switch
q / Esc              Quit (prompt if dirty)
h / Left             Focus section list (left panel)
l / Right            Focus field list (right panel)
j / Down             Move selection down in focused panel
k / Up               Move selection up in focused panel
g / Home             Jump to first item
G / End              Jump to last item
PgDn / PgUp          Page through field list
Enter / Space        Edit/toggle focused field
s                    Save (if dirty)
R                    Reset (confirm dialog)
d                    Reset current field to default
r                    Refresh (reload from disk, warn if dirty)
```

### 6.2 SettingsEdit Mode (popup open)

```
Key                  Action
───                  ──────
Any printable char   Append to edit buffer
Backspace            Remove last char
Ctrl+U               Clear entire buffer
Enter                Confirm: validate → apply → close popup
Esc                  Cancel: discard → close popup
```

---

## 7. Save / Cancel / Reset Flow

### Save (`s` key)

1. `settings_is_dirty` must be true (otherwise no-op)
2. Validate all fields via `validate_all()`
3. Write to temp file: `~/.clx/config.yaml.tmp`
4. Atomic rename to `~/.clx/config.yaml`
5. Update `original_config`, clear dirty, set result message

### Cancel (leave tab when dirty)

Show inline prompt: `"Unsaved changes. [s] Save  [x] Discard  [Esc] Stay"`

### Reset (`R` key)

Confirm dialog → revert `editing_config` to `original_config`.

### Reset Field (`d` key)

Reset single field to `Config::default()` value. No dialog needed.

---

## 8. Validation Strategy

**Point 1: On field edit confirmation (Enter in popup)**
- Parse raw string to target type with range checks
- On failure: show error in popup, edit NOT committed

**Point 2: On save**
- Walk every field, re-validate
- First error highlights offending field, aborts save

**Validator functions:**

```rust
fn validate_u64(s: &str, min: u64, max: u64) -> Result<u64, String>
fn validate_u32(s: &str, min: u32, max: u32) -> Result<u32, String>
fn validate_i64(s: &str, min: i64, max: i64) -> Result<i64, String>
fn validate_f64(s: &str, min: f64, max: f64) -> Result<f64, String>
fn validate_f32(s: &str, min: f32, max: f32) -> Result<f32, String>
fn validate_usize(s: &str, min: usize, max: usize) -> Result<usize, String>
fn validate_nonempty_string(s: &str) -> Result<(), String>
fn validate_url(s: &str) -> Result<(), String>
```

---

## 9. File Changes

### New Files to Create

```
crates/clx/src/dashboard/settings/
├── mod.rs           (module root, re-exports)
├── sections.rs      (SECTIONS const, SectionDef, field defs per section)
├── fields.rs        (FieldDef, FieldWidget enums)
├── config_bridge.rs (get/set/toggle/cycle field values, validators)
└── render.rs        (render_settings_tab, render_edit_popup, render_confirm_dialog)

crates/clx/src/dashboard/ui/settings.rs   (thin shim calling settings::render)
```

### Modified Files

| File | Changes |
|------|---------|
| `crates/clx/src/dashboard/app.rs` | Add `Settings` to `DashboardTab`, extend `ALL` to len 4, add 10 new fields, extend scroll match blocks |
| `crates/clx/src/dashboard/event.rs` | Add `SettingsNav`/`SettingsEdit` handling, route `'4'` key, settings key functions |
| `crates/clx/src/dashboard/ui/mod.rs` | Add `mod settings;`, dispatch arm, update status bar hints |
| `crates/clx-core/src/config.rs` | Add `Config::load_from_file_only()` (load YAML without env overrides) |

### No `Cargo.toml` Changes Required

All needed crates already present: ratatui 0.30, serde_yml, clx-core, dirs.

---

## 10. Data Flow

```
Dashboard startup
  └── App::new() initializes settings fields as None/zero

User presses Tab/4 → DashboardTab::Settings
  └── on_enter_settings_tab()
        ├── Config::load_from_file_only() → settings_original_config
        ├── settings_editing_config = original.clone()
        ├── settings_is_dirty = false
        └── input_mode = SettingsNav

User navigates (j/k/Enter/Space)
  └── handle_settings_nav_key()
        ├── j/k → move field selection
        ├── h/l → switch panel focus (sections ↔ fields)
        ├── Enter on text/number → open popup, SettingsEdit mode
        └── Space on toggle/cycle → modify in-place, recompute dirty

User types in popup (SettingsEdit mode)
  └── handle_settings_edit_key()
        ├── chars → append to buffer
        ├── Enter → validate → apply → close
        └── Esc → discard → close

User presses 's' (save)
  └── settings_save()
        ├── validate_all()
        ├── write temp file → atomic rename
        └── update original, clear dirty
```

---

## 11. Phased Implementation Plan

### Phase 1 — Foundation (read-only navigation)

- [ ] 1.1 Add `Settings` variant to `DashboardTab::ALL` in `app.rs`
- [ ] 1.2 Add `Settings` to `title()` match, update `ALL` length to 4
- [ ] 1.3 Add `Settings` arm to all scroll match blocks (no-ops initially)
- [ ] 1.4 Add `SettingsNav` and `SettingsEdit` variants to `InputMode`
- [ ] 1.5 Add 10 new `App` fields with None/zero defaults
- [ ] 1.6 Add key `'4'` → `DashboardTab::Settings` in `event.rs`
- [ ] 1.7 Add dispatch arm in `ui/mod.rs` (stub initially)
- [ ] 1.8 Create `settings/mod.rs` with module declarations
- [ ] 1.9 Create `sections.rs` with `SECTIONS` const (8 sections)
- [ ] 1.10 Create `fields.rs` with `FieldDef`, `FieldWidget` and all 35 field definitions
- [ ] 1.11 Create `config_bridge.rs` with `get_field_value()` (read-only)
- [ ] 1.12 Create `render.rs` with two-panel read-only display
- [ ] 1.13 Wire `ui/settings.rs` shim
- [ ] 1.14 Implement `on_enter_settings_tab()` on `App`
- [ ] 1.15 Hook tab-entry logic in `event.rs`

**Tests:** tab exists, title correct, key '4' works, tab cycling wraps, get_field_value works for all sections

### Phase 2 — Toggle and Cycle Editing

- [ ] 2.1 Implement `toggle_field()` for all bool fields
- [ ] 2.2 Implement `cycle_field()` for all enum fields
- [ ] 2.3 Implement `recompute_dirty()` via `PartialEq`
- [ ] 2.4 Implement `SettingsNav` key handling (j/k/h/l/Space/Enter)
- [ ] 2.5 Focused row highlight, dirty field yellow coloring
- [ ] 2.6 Tab title `"Settings *"` when dirty
- [ ] 2.7 Status bar hints for Settings tab
- [ ] 2.8 `trust_mode` warning on enable

**Tests:** toggle flips bools, cycle rotates enums, dirty detection works, double-toggle = not dirty

### Phase 3 — Text and Number Editing

- [ ] 3.1 Implement `set_field_value()` with all validators
- [ ] 3.2 Implement all `validate_*` helper functions
- [ ] 3.3 Implement edit popup rendering (Clear + centered Rect)
- [ ] 3.4 Implement `SettingsEdit` key handling (chars, backspace, Ctrl+U, Enter, Esc)
- [ ] 3.5 Validation error display in popup
- [ ] 3.6 Implement `settings_save()` with atomic write
- [ ] 3.7 Wire `'s'` key to save
- [ ] 3.8 Implement `reset_field_to_default()`, wire to `'d'`
- [ ] 3.9 Implement Reset dialog (`'R'`)
- [ ] 3.10 Add `Config::load_from_file_only()` to `clx-core/src/config.rs`

**Tests:** set_field_value round-trips, out-of-range rejected, URL validation, save writes valid YAML, atomic write safety, reset restores defaults

### Phase 4 — Polish and Edge Cases

- [ ] 4.1 Dirty-exit guard (inline prompt on tab leave/quit)
- [ ] 4.2 MCP `command_tools` read-only list display
- [ ] 4.3 Section list scroll for small terminals
- [ ] 4.4 `r` key reload guard when dirty
- [ ] 4.5 Auto-clear `settings_save_result` after 3 seconds
- [ ] 4.6 Custom status bar hints per mode
- [ ] 4.7 Left/right panel focus with `h`/`l` keys
- [ ] 4.8 Truncate long string values in field table
- [ ] 4.9 Config file path + last-saved in header
- [ ] 4.10 Graceful error recovery for malformed YAML

**Tests:** dirty-exit guard behavior, MCP tools list renders, save result auto-clears

---

## 12. Critical Details

### Config Load vs. Env Overrides

Settings tab must load raw YAML values (without env overrides) for editing. Add `Config::load_from_file_only()`:

```rust
pub fn load_from_file_only() -> crate::Result<Config> {
    let config_path = Self::config_dir()?.join("config.yaml");
    if config_path.exists() {
        let content = fs::read_to_string(&config_path)?;
        Ok(serde_yml::from_str(&content)?)
    } else {
        Ok(Config::default())
    }
}
```

### Error Recovery

If `~/.clx/config.yaml` is malformed YAML, show error inline. User can't edit but can run `clx config reset` manually.

### Dirty Detection

```rust
fn recompute_dirty(app: &mut App) {
    app.settings_is_dirty = match (&app.settings_original_config, &app.settings_editing_config) {
        (Some(orig), Some(edit)) => orig != edit,
        _ => false,
    };
}
```

All Config sub-structs derive `PartialEq`. Safe for f32/f64 since validated inputs are never NaN.

---

## 13. Testing Strategy

### Unit Tests (pure logic, no ratatui)

- `get_field_value` returns correct string for every (section, field) using default Config
- `set_field_value` round-trips for all field types
- `toggle_field` flips every bool field
- `cycle_field` cycles all enum fields correctly
- `validate_all` passes for `Config::default()`
- `validate_all` fails on intentionally invalid config
- All `validate_*` functions: boundary values, out-of-range, non-numeric

### App State Tests

- Tab navigation includes Settings
- `on_enter_settings_tab` initializes correctly
- `recompute_dirty` detects changes

### Integration Tests

- `settings_save_writes_valid_yaml`: edit field, save, parse result
- `settings_save_atomic`: verify original intact on write failure
- `settings_load_invalid_yaml`: graceful error state

### Render Tests (TestBackend)

- `render_settings_tab` does not panic with default state
- `render_edit_popup` renders with non-empty buffer
- Dirty indicator shown when `is_dirty = true`

**Total: ~37 implementation tasks, ~27 tests**

---

## 14. Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|-----------|
| `match (section, field)` in config_bridge grows large | Medium | 35 arms, structured with comments per section; acceptable |
| Key conflict: `'s'` is sort in other tabs, save in Settings | None | Mode-specific dispatch; no conflict |
| Env-override values confusion | Low | `load_from_file_only()` + inline notice |
| Terminal height < 24 lines | Low | Responsive min-height guards in Phase 4 |
| `f64` PartialEq with NaN | Low | Validated inputs are never NaN |

---

## 15. Future Work (Post Phase 4)

- Phase 5: Editable `McpCommandTool` list (add/remove entries)
- Phase 5: Rule editing from Rules tab (add/edit/delete patterns)
- Phase 5: Ollama model picker (query available models from API)
- Phase 5: Config diff view (show changes before save)
