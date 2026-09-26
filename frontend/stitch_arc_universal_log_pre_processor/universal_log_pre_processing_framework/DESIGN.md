---
name: Universal Log Pre-Processing Framework
colors:
  surface: '#faf8ff'
  surface-dim: '#d2d9f4'
  surface-bright: '#faf8ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f2f3ff'
  surface-container: '#eaedff'
  surface-container-high: '#e2e7ff'
  surface-container-highest: '#dae2fd'
  on-surface: '#131b2e'
  on-surface-variant: '#584237'
  inverse-surface: '#283044'
  inverse-on-surface: '#eef0ff'
  outline: '#8c7164'
  outline-variant: '#e0c0b1'
  surface-tint: '#9d4300'
  primary: '#9d4300'
  on-primary: '#ffffff'
  primary-container: '#f97316'
  on-primary-container: '#582200'
  inverse-primary: '#ffb690'
  secondary: '#0051d5'
  on-secondary: '#ffffff'
  secondary-container: '#316bf3'
  on-secondary-container: '#fefcff'
  tertiary: '#6d3bd7'
  on-tertiary: '#ffffff'
  tertiary-container: '#a985ff'
  on-tertiary-container: '#3e0096'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#ffdbca'
  primary-fixed-dim: '#ffb690'
  on-primary-fixed: '#341100'
  on-primary-fixed-variant: '#783200'
  secondary-fixed: '#dbe1ff'
  secondary-fixed-dim: '#b4c5ff'
  on-secondary-fixed: '#00174b'
  on-secondary-fixed-variant: '#003ea8'
  tertiary-fixed: '#e9ddff'
  tertiary-fixed-dim: '#d0bcff'
  on-tertiary-fixed: '#23005c'
  on-tertiary-fixed-variant: '#5516be'
  background: '#faf8ff'
  on-background: '#131b2e'
  surface-variant: '#dae2fd'
typography:
  display:
    fontFamily: Inter
    fontSize: 1.75rem
    fontWeight: '700'
    lineHeight: 2.25rem
    letterSpacing: -0.025em
  headline-lg:
    fontFamily: Inter
    fontSize: 1.5rem
    fontWeight: '700'
    lineHeight: 2rem
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 1.25rem
    fontWeight: '600'
    lineHeight: 1.75rem
    letterSpacing: -0.015em
  headline-sm:
    fontFamily: Inter
    fontSize: 1rem
    fontWeight: '600'
    lineHeight: 1.5rem
  body-lg:
    fontFamily: Inter
    fontSize: 0.9375rem
    fontWeight: '400'
    lineHeight: 1.5rem
  body-md:
    fontFamily: Inter
    fontSize: 0.875rem
    fontWeight: '400'
    lineHeight: 1.375rem
  body-sm:
    fontFamily: Inter
    fontSize: 0.75rem
    fontWeight: '400'
    lineHeight: 1.125rem
  label-lg:
    fontFamily: Inter
    fontSize: 0.875rem
    fontWeight: '600'
    lineHeight: 1.25rem
  label-md:
    fontFamily: Inter
    fontSize: 0.75rem
    fontWeight: '500'
    lineHeight: 1rem
    letterSpacing: 0.01em
  label-sm:
    fontFamily: Inter
    fontSize: 0.6875rem
    fontWeight: '600'
    lineHeight: 0.875rem
    letterSpacing: 0.025em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 0.75rem
    fontWeight: '400'
    lineHeight: 1.25rem
  code-xs:
    fontFamily: JetBrains Mono
    fontSize: 0.6875rem
    fontWeight: '400'
    lineHeight: 1rem
  stat-value:
    fontFamily: Inter
    fontSize: 1.625rem
    fontWeight: '700'
    lineHeight: 2rem
    letterSpacing: -0.03em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-lg: 1.5rem
  margin: 1.5rem
  margin-sm: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
  space-2xl: 2rem
---

## Brand & Style

The design system establishes a high-performance, mission-critical workspace tailored for cybersecurity engineers, SecOps analysts, and enterprise data architects. It balances maximum information density with calm structural legibility. The visual character communicates precision, zero-latency throughput, and ironclad operational control.

The aesthetic fuses **Corporate / Modern enterprise utility** with **technical command-center aesthetics**:
- A dark, deep-navy contextual navigation anchor (#0A1325 through #0D1B36) with subtle luminous energy waves reinforces continuous protection and high-throughput monitoring.
- The primary operations workspace uses crisp light neutral containers (#FFFFFF and #F8FAFC) bordered by hairline structural dividers (#E2E8F0) to ensure high reading ergonomics across thousands of log lines and multi-column telemetry tables.
- Energetic functional accents command immediate action: industrial orange highlights direct interactive navigation and primary workflows, high-precision cobalt blue powers data actions, deep emerald denotes verified pipeline states, while critical crimson and warning amber flag pipeline degradations instantly.
- Artificial intelligence workflows feature specialized royal violet tones to clearly delineate autonomous inference from deterministic rule matching.

## Colors

The palette establishes an unambiguous visual hierarchy where operational state, urgency, and identity are understood at a glance.

### Palette Architecture
- **Primary Orange (`#F97316` / Hover `#EA580C`):** Used strictly for high-priority interactive touchpoints, primary conversion buttons, and the active navigation pill within the dark frame.
- **Secondary Tech Blue (`#2563EB` / Light `#3B82F6`):** Governs data actions, interactive links, telemetry series lines, and ingestion triggers.
- **Tertiary AI Purple (`#8B5CF6` / Deep `#7C3AED`):** Dedicated to machine-learning assistance, Grok parsing inference, AI suggestions, and neural mapping indicators.
- **Success Emerald (`#10B981`):** Applied to validated logs, 99%+ normalization badges, healthy source indicators, and active parsers.
- **Alert & Danger Red (`#EF4444`):** Flags ingestion failures, quarantine logs, validation drop-offs, and critical system anomalies.
- **Warning Amber (`#F59E0B`):** Denotes format discrepancies, pending human reviews, and parse rate spikes.
- **Deep Navy Command (`#0A1325` to `#0D1B36`):** The steadfast lateral navigation chassis, featuring subtle cyan/blue luminous gradients along the lower spine.
- **Neutral Light Workspace (`#F8FAFC` base, `#FFFFFF` cards, `#0F172A` high-contrast typography):** Provides pristine daylight contrast for data-dense grids and multi-line syntax blocks.

## Typography

Typographic execution relies on **Inter** as the foundational sans-serif across interface levels, pairing seamlessly with **JetBrains Mono** for payload inspection, raw syslog streams, Grok pattern templates, and JSON field schemas.

### Hierarchy & Treatment
- **System Metrics & Display Counters (`stat-value`):** Bold, compact numerical rendering designed for scan-ability across high-density multi-card rows.
- **Section Headers (`headline-lg` / `headline-md`):** High contrast `#0F172A` paired with `#64748B` supporting descriptions to anchor view contexts.
- **Log Payloads & Terminal Previews:** Always rendered with `JetBrains Mono` at `0.75rem` or `0.6875rem` with high syntax token differentiation (e.g., green for timestamps, orange for severity codes, and purple for IP addresses).
- **Data Table Cells:** Strictly sized at `body-sm` (`0.75rem` to `0.8125rem`) to maximize visible records per screen viewport without line clipping.

## Layout & Spacing

The architecture utilizes a locked 240px lateral sidebar on desktop paired with a fluid, multi-column light-mode analytical canvas. 

### Grid & Density Rules
- **Canvas Shell:** Fluid workspace conforming to viewport bounds with a minimum content width of 1180px, constrained by standard padding of 24px (`space-xl`).
- **Metric Row Composition:** Standard 4-up to 7-up auto-fitting card arrays with 16px gaps (`space-lg`), collapsing into 2-column or horizontally scrolling carousels on tablet screens.
- **Two-Thirds / One-Third Master Layout:** Complex screens (e.g., Format Detection, Parser Registry, Quarantine, Event Viewer) partition real estate into a 65% aggregate grid view and a 35% fixed-inspector panel for rapid drill-down without context departure.
- **Dense Data Rhythms:** Internal card padding is locked to 16px (`space-lg`) or 20px, while compact table rows maintain 36px to 40px row heights with 12px horizontal cell padding.

## Elevation & Depth

Visual separation is attained through clean, hairline perimeter boundaries combined with subtle, ambient drop shadows rather than heavy skeuomorphic shading.

### Elevation Hierarchy
- **Level 0 (Workspace Canvas):** Flat `#F8FAFC` base surface creating maximum perimeter differentiation against white card modules.
- **Level 1 (Operational Cards & Data Tiles):** `#FFFFFF` surface bounded by a crisp 1px solid `#E2E8F0` border with an ultra-light ambient shadow: `0 1px 3px 0 rgba(15, 23, 42, 0.04), 0 1px 2px -1px rgba(15, 23, 42, 0.03)`.
- **Level 2 (Dropdowns, Overlays & Sticky Bars):** Elevated floating menus, popover filters, and action sheets rely on `0 10px 15px -3px rgba(15, 23, 42, 0.08), 0 4px 6px -4px rgba(15, 23, 42, 0.04)` enclosed with a `#CBD5E1` boundary.
- **Dark Sidebar Horizon:** Deep dark navy (`#0A1325`) sits along the absolute left elevation plane, absorbing visual weight and framing the white workspace. Internal subtle vector illumination arcs give depth without distraction.
- **Code & Syntax Wells:** Recessed into `#0B132B` (dark syntax mode) or `#F1F5F9` (light schema mode) with an inset border `#0000000a` creating a shallow inset container.

## Shapes

The design system maintains a balanced, contemporary rounded corner language (`roundedness: 2`).

### Radius Assignments
- **Structural Cards & Panels (`rounded-xl` / 12px–14px):** Applied to primary dashboard modules, analytic charting cards, inspection panes, and data table enclosures.
- **Interactive Controls (`rounded-lg` / 8px):** Applied to text input fields, dropdown selectors, standard buttons, and tab switchers.
- **Status Badges & Delta Chips (`rounded-full` / Pill):** Applied to operational status badges (e.g., Active, Success, Pending, Failed), delta percentages, and user avatar badges.
- **Active Navigation Indicator (`rounded-lg` / 8px):** Prominently encapsulates the active sidebar item in full-width orange fill with rounded corners.

## Components

### Buttons
- **Primary Action:** Solid Orange (`#F97316`) background, white text (`#FFFFFF`), `font-weight: 600`, 8px radius (`rounded-lg`), subtle press elevation, and `#EA580C` hover state.
- **Secondary / Tech Action:** Solid Blue (`#2563EB`) or Blue Outline (`1px solid #2563EB` with `#EFF6FF` hover) for log ingestion triggers, schema generation, and query execution.
- **Subtle / Secondary Utility:** Crisp border (`1px solid #E2E8F0`), white background, text `#334155`, `#F8FAFC` hover state.
- **Destructive:** Border or solid `#EF4444` for parser deprecation or quarantine deletion.

### Metric KPI Cards
- Elevated card containing an 36x36px rounded square icon container tinted by metric classification (e.g., soft blue, emerald, amber, purple).
- Compact label at top (`0.75rem`, `#64748B`), bold counter (`1.625rem`, `#0F172A`), followed by a directional comparison badge (green upward chevron for healthy throughput, red upward for errors).

### Status Badges & Pills
- **Active / Success:** Soft green pill (`#DCFCE7` fill, `#15803D` text, dot indicator `#10B981`).
- **Critical / Failed:** Soft red pill (`#FEE2E2` fill, `#B91C1C` text, dot indicator `#EF4444`).
- **Pending / Warning:** Soft amber pill (`#FEF3C7` fill, `#B45309` text, dot indicator `#F59E0B`).
- **AI Suggested / Parsed:** Soft violet pill (`#F3E8FF` fill, `#6B21A8` text).

### Data Tables
- Header row styled with `#F8FAFC` background, hairline bottom border (`#E2E8F0`), uppercase or small medium label font (`#64748B`, `0.75rem`).
- Hover states highlight active rows in `#F8FAFC`.
- Integrated action column contains micro icon buttons (view, edit, more menu) with 32x32px hit targets.

### Input Fields & Search Bars
- Inset padding (`8px 12px`), 1px border (`#CBD5E1`), background `#FFFFFF`, rounded 8px.
- Focus state activates an intense 2px blue ring (`#3B82F6`) with no offset.
- Global search includes integrated left search icon and keyboard shortcut badge (`Ctrl + K`).

### Code & Parser Inspectors
- Dark terminal theme (`#0D1B2A` background) with numbered line gutter, high-contrast tokenized syntax colors, and top-right sticky copy button.
- Split preview panes for side-by-side Raw Log, Parsed Output, and Normalized Schema comparison.