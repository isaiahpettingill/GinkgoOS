#![no_std]

//! A deterministic, allocation-backed scrolling layout.
//!
//! Every window occupies exactly one column. Column widths are expressed in
//! per-mille proportions of the current output width, so `Proportion::new(500)`
//! is 50%. The focused column is automatically scrolled into view.
//!
//! This crate only computes state and geometry. It has no hardware, process,
//! compositor, or platform dependencies.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::{max, min};

/// An application-defined window identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowId(pub u64);

/// An application-defined workspace identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceId(pub u64);

/// A two-dimensional size in output pixels.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }
}

/// Insets between a window's outer and client rectangles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Insets {
    pub left: u32,
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
}

impl Insets {
    pub const ZERO: Self = Self::new(0, 0, 0, 0);

    pub const fn new(left: u32, top: u32, right: u32, bottom: u32) -> Self {
        Self {
            left,
            top,
            right,
            bottom,
        }
    }
}

/// A rectangle in output coordinates.
///
/// Signed origins allow columns outside the viewport to retain their true
/// scrolled positions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rect {
    pub x: i64,
    pub y: i64,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: i64, y: i64, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn right(self) -> i64 {
        self.x.saturating_add(i64::from(self.width))
    }

    pub fn bottom(self) -> i64 {
        self.y.saturating_add(i64::from(self.height))
    }

    /// Returns the non-empty intersection of two rectangles.
    pub fn intersection(self, other: Self) -> Option<Self> {
        let left = max(self.x, other.x);
        let top = max(self.y, other.y);
        let right = min(self.right(), other.right());
        let bottom = min(self.bottom(), other.bottom());

        if right <= left || bottom <= top {
            return None;
        }

        Some(Self::new(
            left,
            top,
            (right - left) as u32,
            (bottom - top) as u32,
        ))
    }

    /// Applies insets, saturating to an empty rectangle if they consume it.
    pub fn inset(self, insets: Insets) -> Self {
        let left = min(insets.left, self.width);
        let top = min(insets.top, self.height);
        let horizontal = insets.left.saturating_add(insets.right);
        let vertical = insets.top.saturating_add(insets.bottom);

        Self::new(
            self.x.saturating_add(i64::from(left)),
            self.y.saturating_add(i64::from(top)),
            self.width.saturating_sub(horizontal),
            self.height.saturating_sub(vertical),
        )
    }
}

/// A positive per-mille proportion of the output width.
///
/// `500` means 50%, `1000` means 100%, and values above `1000` are allowed for
/// columns wider than the viewport.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Proportion(u16);

impl Proportion {
    pub const HALF: Self = Self(500);
    pub const FULL: Self = Self(1000);

    pub const fn new(per_mille: u16) -> Option<Self> {
        if per_mille == 0 {
            None
        } else {
            Some(Self(per_mille))
        }
    }

    pub const fn per_mille(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for Proportion {
    type Error = LayoutError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(LayoutError::InvalidProportion)
    }
}

impl From<Proportion> for u16 {
    fn from(value: Proportion) -> Self {
        value.per_mille()
    }
}

/// Public state for one window/column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Column {
    pub window: WindowId,
    pub width: Proportion,
}

/// Geometry produced for a window in the active workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Placement {
    pub window: WindowId,
    /// The decorated rectangle, which may extend outside the output.
    pub outer: Rect,
    /// `outer` reduced by the configured decoration insets.
    pub client: Rect,
    /// The portion of `outer` visible within the output, or `None` if clipped.
    pub visible: Option<Rect>,
    pub focused: bool,
}

/// Direction used by relative focus and movement operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Previous,
    Next,
}

/// Horizontal position of a focused column within the output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HorizontalAlignment {
    Left,
    Center,
    Right,
}

/// Errors from layout operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    DuplicateWindow,
    DuplicateWorkspace,
    InvalidColumnIndex,
    InvalidProportion,
    LastWorkspace,
    UnknownWindow,
    UnknownWorkspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FullscreenRestore {
    window: WindowId,
    column_index: usize,
    width: Proportion,
    viewport: i64,
    focused: Option<WindowId>,
}

#[derive(Debug)]
struct Workspace {
    id: WorkspaceId,
    columns: Vec<Column>,
    focused: Option<usize>,
    viewport: i64,
    fullscreen: Option<FullscreenRestore>,
}

impl Workspace {
    fn new(id: WorkspaceId) -> Self {
        Self {
            id,
            columns: Vec::new(),
            focused: None,
            viewport: 0,
            fullscreen: None,
        }
    }

    fn focused_window(&self) -> Option<WindowId> {
        self.focused
            .and_then(|index| self.columns.get(index))
            .map(|column| column.window)
    }
}

/// A pure scrolling layout containing one or more workspaces.
#[derive(Debug)]
pub struct Layout {
    output: Size,
    decorations: Insets,
    workspaces: Vec<Workspace>,
    active: usize,
}

impl Layout {
    /// Creates a layout with workspace `WorkspaceId(0)` active.
    pub fn new(output: Size) -> Self {
        Self::with_workspace(output, WorkspaceId(0))
    }

    /// Creates a layout with the supplied initial workspace active.
    pub fn with_workspace(output: Size, workspace: WorkspaceId) -> Self {
        Self {
            output,
            decorations: Insets::ZERO,
            workspaces: alloc::vec![Workspace::new(workspace)],
            active: 0,
        }
    }

    pub const fn output_size(&self) -> Size {
        self.output
    }

    /// Changes output dimensions while keeping focused columns visible and
    /// preserving their output-relative scroll positions.
    pub fn set_output_size(&mut self, output: Size) {
        let previous_width = self.output.width;
        self.output = output;
        for workspace in &mut self.workspaces {
            workspace.viewport = scale_position(workspace.viewport, previous_width, output.width);
            if let Some(restore) = &mut workspace.fullscreen {
                restore.viewport = scale_position(restore.viewport, previous_width, output.width);
            }
            ensure_focused_visible(workspace, output.width);
        }
    }

    pub const fn decorations(&self) -> Insets {
        self.decorations
    }

    pub fn set_decorations(&mut self, decorations: Insets) {
        self.decorations = decorations;
    }

    pub fn active_workspace(&self) -> WorkspaceId {
        self.workspaces[self.active].id
    }

    pub fn workspace_count(&self) -> usize {
        self.workspaces.len()
    }

    pub fn workspace_ids(&self) -> impl ExactSizeIterator<Item = WorkspaceId> + '_ {
        self.workspaces.iter().map(|workspace| workspace.id)
    }

    pub fn add_workspace(&mut self, workspace: WorkspaceId) -> Result<(), LayoutError> {
        if self.workspace_index(workspace).is_some() {
            return Err(LayoutError::DuplicateWorkspace);
        }
        self.workspaces.push(Workspace::new(workspace));
        Ok(())
    }

    /// Removes an empty workspace. The final workspace cannot be removed.
    pub fn remove_workspace(&mut self, workspace: WorkspaceId) -> Result<(), LayoutError> {
        let index = self
            .workspace_index(workspace)
            .ok_or(LayoutError::UnknownWorkspace)?;
        if self.workspaces.len() == 1 {
            return Err(LayoutError::LastWorkspace);
        }
        if !self.workspaces[index].columns.is_empty() {
            return Err(LayoutError::InvalidColumnIndex);
        }

        self.workspaces.remove(index);
        if self.active == index {
            self.active = min(index, self.workspaces.len() - 1);
        } else if self.active > index {
            self.active -= 1;
        }
        Ok(())
    }

    pub fn set_active_workspace(&mut self, workspace: WorkspaceId) -> Result<(), LayoutError> {
        self.active = self
            .workspace_index(workspace)
            .ok_or(LayoutError::UnknownWorkspace)?;
        Ok(())
    }

    pub fn columns(&self, workspace: WorkspaceId) -> Result<&[Column], LayoutError> {
        let index = self
            .workspace_index(workspace)
            .ok_or(LayoutError::UnknownWorkspace)?;
        Ok(&self.workspaces[index].columns)
    }

    pub fn focused_window(&self) -> Option<WindowId> {
        self.workspaces[self.active].focused_window()
    }

    pub fn focused_window_in(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<WindowId>, LayoutError> {
        let index = self
            .workspace_index(workspace)
            .ok_or(LayoutError::UnknownWorkspace)?;
        Ok(self.workspaces[index].focused_window())
    }

    pub fn viewport(&self) -> i64 {
        self.workspaces[self.active].viewport
    }

    pub fn viewport_in(&self, workspace: WorkspaceId) -> Result<i64, LayoutError> {
        let index = self
            .workspace_index(workspace)
            .ok_or(LayoutError::UnknownWorkspace)?;
        Ok(self.workspaces[index].viewport)
    }

    pub fn contains(&self, window: WindowId) -> bool {
        self.find_window(window).is_some()
    }

    /// Inserts after the focused column, or at the end if there is no focus.
    /// The inserted window becomes focused.
    pub fn insert(&mut self, window: WindowId, width: Proportion) -> Result<(), LayoutError> {
        let index = self.workspaces[self.active]
            .focused
            .map_or(self.workspaces[self.active].columns.len(), |focused| {
                focused + 1
            });
        self.insert_at(index, window, width)
    }

    /// Inserts in the active workspace at an exact column index.
    pub fn insert_at(
        &mut self,
        index: usize,
        window: WindowId,
        width: Proportion,
    ) -> Result<(), LayoutError> {
        if self.contains(window) {
            return Err(LayoutError::DuplicateWindow);
        }

        self.finish_fullscreen(self.active);
        let workspace = &mut self.workspaces[self.active];
        if index > workspace.columns.len() {
            return Err(LayoutError::InvalidColumnIndex);
        }

        workspace.columns.insert(index, Column { window, width });
        workspace.focused = Some(index);
        ensure_focused_visible(workspace, self.output.width);
        Ok(())
    }

    /// Removes a window from whichever workspace contains it.
    ///
    /// If it was focused, focus moves to the following column, or the previous
    /// column when the removed window was last.
    pub fn remove(&mut self, window: WindowId) -> Result<Column, LayoutError> {
        let (workspace_index, _) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        self.finish_fullscreen(workspace_index);
        let (_, column_index) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        let workspace = &mut self.workspaces[workspace_index];
        let focused_window = workspace.focused_window();
        let removed = workspace.columns.remove(column_index);

        workspace.focused = if workspace.columns.is_empty() {
            None
        } else if focused_window == Some(window) {
            Some(min(column_index, workspace.columns.len() - 1))
        } else {
            focused_window.and_then(|focused| {
                workspace
                    .columns
                    .iter()
                    .position(|column| column.window == focused)
            })
        };
        ensure_focused_visible(workspace, self.output.width);
        Ok(removed)
    }

    /// Focuses a window and activates its workspace.
    pub fn focus(&mut self, window: WindowId) -> Result<(), LayoutError> {
        let (workspace_index, _) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        if self.workspaces[workspace_index]
            .fullscreen
            .is_some_and(|restore| restore.window == window)
        {
            self.active = workspace_index;
            return Ok(());
        }

        self.finish_fullscreen(workspace_index);
        let (_, column_index) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;

        self.active = workspace_index;
        self.workspaces[workspace_index].focused = Some(column_index);
        ensure_focused_visible(&mut self.workspaces[workspace_index], self.output.width);
        Ok(())
    }

    pub fn focus_relative(&mut self, direction: Direction) -> bool {
        let workspace = &self.workspaces[self.active];
        let focused = workspace
            .fullscreen
            .map_or(workspace.focused, |restore| Some(restore.column_index));
        let Some(focused) = focused else {
            return false;
        };
        let next = match direction {
            Direction::Previous if focused > 0 => focused - 1,
            Direction::Next if focused + 1 < workspace.columns.len() => focused + 1,
            _ => return false,
        };

        self.finish_fullscreen(self.active);
        let workspace = &mut self.workspaces[self.active];
        workspace.focused = Some(next);
        ensure_focused_visible(workspace, self.output.width);
        true
    }

    /// Moves a window to an exact index in its existing workspace.
    pub fn move_window(&mut self, window: WindowId, new_index: usize) -> Result<(), LayoutError> {
        let (workspace_index, _) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        self.finish_fullscreen(workspace_index);
        let (_, old_index) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        let workspace = &mut self.workspaces[workspace_index];
        if new_index >= workspace.columns.len() {
            return Err(LayoutError::InvalidColumnIndex);
        }

        let focused_window = workspace.focused_window();
        let column = workspace.columns.remove(old_index);
        workspace.columns.insert(new_index, column);
        workspace.focused = focused_window.and_then(|focused| {
            workspace
                .columns
                .iter()
                .position(|column| column.window == focused)
        });
        ensure_focused_visible(workspace, self.output.width);
        Ok(())
    }

    /// Moves the focused column one position. Returns `false` at an edge or
    /// when the active workspace is empty.
    pub fn move_focused(&mut self, direction: Direction) -> bool {
        let workspace = &self.workspaces[self.active];
        let fullscreen = workspace.fullscreen.is_some();
        let (index, window) = if let Some(restore) = workspace.fullscreen {
            (restore.column_index, restore.window)
        } else {
            let Some(index) = workspace.focused else {
                return false;
            };
            (index, workspace.columns[index].window)
        };
        let new_index = match direction {
            Direction::Previous if index > 0 => index - 1,
            Direction::Next if index + 1 < workspace.columns.len() => index + 1,
            _ => return false,
        };

        if fullscreen {
            self.finish_fullscreen(self.active);
            self.workspaces[self.active].focused = Some(index);
        }
        self.move_window(window, new_index).is_ok()
    }

    /// Aligns the focused column to an output edge or center.
    ///
    /// Endpoint columns may scroll past the ordinary content bounds so every
    /// alignment is available for narrow, full-width, and oversized columns.
    /// Returns `false` when the active workspace has no focused column.
    pub fn align_focused(&mut self, alignment: HorizontalAlignment) -> bool {
        let fullscreen_window = self.workspaces[self.active]
            .fullscreen
            .map(|restore| restore.window);
        self.finish_fullscreen(self.active);
        let workspace = &mut self.workspaces[self.active];
        if let Some(window) = fullscreen_window {
            workspace.focused = workspace
                .columns
                .iter()
                .position(|column| column.window == window);
        }
        let Some(index) = workspace.focused else {
            return false;
        };
        let Some(column) = workspace.columns.get(index) else {
            workspace.focused = None;
            return false;
        };

        let left = column_left(workspace, self.output.width, index);
        let width = i64::from(pixel_width(self.output.width, column.width));
        let output_width = i64::from(self.output.width);
        workspace.viewport = match alignment {
            HorizontalAlignment::Left => left,
            HorizontalAlignment::Center => {
                left.saturating_add(width.saturating_sub(output_width) / 2)
            }
            HorizontalAlignment::Right => left.saturating_add(width).saturating_sub(output_width),
        };
        clamp_viewport(workspace, self.output.width);
        true
    }

    pub fn set_width(&mut self, window: WindowId, width: Proportion) -> Result<(), LayoutError> {
        let (workspace_index, _) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        self.finish_fullscreen(workspace_index);
        let (_, column_index) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        let workspace = &mut self.workspaces[workspace_index];
        workspace.columns[column_index].width = width;
        ensure_focused_visible(workspace, self.output.width);
        Ok(())
    }

    /// Adds a signed per-mille delta to a window's width, saturating at the
    /// valid [`Proportion`] limits.
    pub fn adjust_width(
        &mut self,
        window: WindowId,
        delta_per_mille: i32,
    ) -> Result<(), LayoutError> {
        let (workspace_index, _) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        self.finish_fullscreen(workspace_index);
        let (_, column_index) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        let workspace = &mut self.workspaces[workspace_index];
        let current = i64::from(workspace.columns[column_index].width.per_mille());
        let adjusted = current
            .saturating_add(i64::from(delta_per_mille))
            .clamp(1, i64::from(u16::MAX)) as u16;
        workspace.columns[column_index].width = Proportion(adjusted);
        ensure_focused_visible(workspace, self.output.width);
        Ok(())
    }

    /// Temporarily presents one window over the full output without decoration
    /// insets. Its prior column index, width, viewport, and focus are restored
    /// by [`Self::exit_fullscreen`].
    pub fn enter_fullscreen(&mut self, window: WindowId) -> Result<(), LayoutError> {
        let (workspace_index, _) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        self.finish_fullscreen(workspace_index);
        let (_, column_index) = self.find_window(window).ok_or(LayoutError::UnknownWindow)?;
        let workspace = &mut self.workspaces[workspace_index];
        let restore = FullscreenRestore {
            window,
            column_index,
            width: workspace.columns[column_index].width,
            viewport: workspace.viewport,
            focused: workspace.focused_window(),
        };

        let mut column = workspace.columns.remove(column_index);
        column.width = Proportion::FULL;
        workspace.columns.insert(0, column);
        workspace.focused = Some(0);
        workspace.viewport = 0;
        workspace.fullscreen = Some(restore);
        self.active = workspace_index;
        Ok(())
    }

    /// Exits fullscreen in the active workspace. Returns whether it was active.
    pub fn exit_fullscreen(&mut self) -> bool {
        self.finish_fullscreen(self.active)
    }

    pub fn fullscreen_window(&self) -> Option<WindowId> {
        self.workspaces[self.active]
            .fullscreen
            .map(|state| state.window)
    }

    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen_window().is_some()
    }

    /// Computes placements for every column in the active workspace.
    ///
    /// During fullscreen, only the fullscreen window is returned.
    pub fn placements(&self) -> Vec<Placement> {
        let workspace = &self.workspaces[self.active];
        let output_rect = Rect::new(0, 0, self.output.width, self.output.height);

        if let Some(fullscreen) = workspace.fullscreen {
            return alloc::vec![Placement {
                window: fullscreen.window,
                outer: output_rect,
                client: output_rect,
                visible: output_rect.intersection(output_rect),
                focused: true,
            }];
        }

        let mut placements = Vec::with_capacity(workspace.columns.len());
        let mut left = 0_i64;
        for (index, column) in workspace.columns.iter().enumerate() {
            let width = pixel_width(self.output.width, column.width);
            let outer = Rect::new(
                left.saturating_sub(workspace.viewport),
                0,
                width,
                self.output.height,
            );
            placements.push(Placement {
                window: column.window,
                outer,
                client: outer.inset(self.decorations),
                visible: outer.intersection(output_rect),
                focused: workspace.focused == Some(index),
            });
            left = left.saturating_add(i64::from(width));
        }
        placements
    }

    fn workspace_index(&self, workspace: WorkspaceId) -> Option<usize> {
        self.workspaces
            .iter()
            .position(|candidate| candidate.id == workspace)
    }

    fn find_window(&self, window: WindowId) -> Option<(usize, usize)> {
        self.workspaces
            .iter()
            .enumerate()
            .find_map(|(workspace_index, workspace)| {
                workspace
                    .columns
                    .iter()
                    .position(|column| column.window == window)
                    .map(|column_index| (workspace_index, column_index))
            })
    }

    fn finish_fullscreen(&mut self, workspace_index: usize) -> bool {
        let workspace = &mut self.workspaces[workspace_index];
        let Some(restore) = workspace.fullscreen.take() else {
            return false;
        };
        let Some(current_index) = workspace
            .columns
            .iter()
            .position(|column| column.window == restore.window)
        else {
            return true;
        };

        let mut column = workspace.columns.remove(current_index);
        column.width = restore.width;
        let restored_index = min(restore.column_index, workspace.columns.len());
        workspace.columns.insert(restored_index, column);
        workspace.focused = restore.focused.and_then(|focused| {
            workspace
                .columns
                .iter()
                .position(|column| column.window == focused)
        });
        if workspace.focused.is_none() {
            workspace.focused = Some(restored_index);
        }
        workspace.viewport = restore.viewport;
        clamp_viewport(workspace, self.output.width);
        true
    }
}

fn pixel_width(output_width: u32, proportion: Proportion) -> u32 {
    if output_width == 0 {
        return 0;
    }

    let scaled = u64::from(output_width)
        .saturating_mul(u64::from(proportion.per_mille()))
        .saturating_add(500)
        / 1000;
    min(max(scaled, 1), u64::from(u32::MAX)) as u32
}

fn total_width(workspace: &Workspace, output_width: u32) -> i64 {
    workspace.columns.iter().fold(0_i64, |total, column| {
        total.saturating_add(i64::from(pixel_width(output_width, column.width)))
    })
}

fn column_left(workspace: &Workspace, output_width: u32, index: usize) -> i64 {
    workspace.columns[..index]
        .iter()
        .fold(0_i64, |left, column| {
            left.saturating_add(i64::from(pixel_width(output_width, column.width)))
        })
}

fn clamp_viewport(workspace: &mut Workspace, output_width: u32) {
    let Some(first) = workspace.columns.first() else {
        workspace.viewport = 0;
        return;
    };
    let Some(last) = workspace.columns.last() else {
        workspace.viewport = 0;
        return;
    };

    let output_width = i64::from(output_width);
    let first_width = i64::from(pixel_width(output_width as u32, first.width));
    let last_width = i64::from(pixel_width(output_width as u32, last.width));
    let total = total_width(workspace, output_width as u32);
    let last_left = total.saturating_sub(last_width);
    let minimum = first_width.saturating_sub(output_width).min(0);
    let maximum = last_left.max(total.saturating_sub(output_width)).max(0);
    workspace.viewport = workspace.viewport.clamp(minimum, maximum);
}

fn scale_position(position: i64, old_width: u32, new_width: u32) -> i64 {
    if old_width == 0 || position == 0 {
        return 0;
    }

    let numerator = i128::from(position).saturating_mul(i128::from(new_width));
    let divisor = i128::from(old_width);
    let half = divisor / 2;
    let rounded = if numerator >= 0 {
        numerator.saturating_add(half) / divisor
    } else {
        numerator.saturating_sub(half) / divisor
    };
    rounded.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn ensure_focused_visible(workspace: &mut Workspace, output_width: u32) {
    clamp_viewport(workspace, output_width);
    let Some(index) = workspace.focused else {
        return;
    };
    let Some(column) = workspace.columns.get(index) else {
        workspace.focused = None;
        return;
    };

    let left = column_left(workspace, output_width, index);
    let width = i64::from(pixel_width(output_width, column.width));
    let viewport_width = i64::from(output_width);
    let right = left.saturating_add(width);

    if width > viewport_width || left < workspace.viewport {
        workspace.viewport = left;
    } else if right > workspace.viewport.saturating_add(viewport_width) {
        workspace.viewport = right.saturating_sub(viewport_width);
    }
    clamp_viewport(workspace, output_width);
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: WindowId = WindowId(1);
    const B: WindowId = WindowId(2);
    const C: WindowId = WindowId(3);
    const D: WindowId = WindowId(4);
    const MAIN: WorkspaceId = WorkspaceId(0);
    const OTHER: WorkspaceId = WorkspaceId(7);

    fn proportion(value: u16) -> Proportion {
        Proportion::new(value).unwrap()
    }

    fn windows(layout: &Layout, workspace: WorkspaceId) -> Vec<WindowId> {
        layout
            .columns(workspace)
            .unwrap()
            .iter()
            .map(|column| column.window)
            .collect()
    }

    #[test]
    fn proportions_are_per_mille_and_may_exceed_the_output() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(500)).unwrap();
        layout.insert(B, proportion(1500)).unwrap();

        let placements = layout.placements();
        assert_eq!(placements[0].outer.width, 500);
        assert_eq!(placements[1].outer.width, 1500);
        assert_eq!(Proportion::new(0), None);
        assert_eq!(Proportion::try_from(0), Err(LayoutError::InvalidProportion));
    }

    #[test]
    fn insertion_scrolls_each_focused_column_into_view() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(600)).unwrap();
        layout.insert(B, proportion(600)).unwrap();
        layout.insert(C, proportion(600)).unwrap();

        assert_eq!(layout.focused_window(), Some(C));
        assert_eq!(layout.viewport(), 800);
        let placements = layout.placements();
        assert_eq!(placements[0].outer.x, -800);
        assert_eq!(placements[0].visible, None);
        assert_eq!(placements[1].outer.x, -200);
        assert_eq!(placements[1].visible, Some(Rect::new(0, 0, 400, 600)));
        assert_eq!(placements[2].outer.x, 400);
        assert_eq!(placements[2].visible, Some(Rect::new(400, 0, 600, 600)));
    }

    #[test]
    fn focus_scrolls_in_both_directions_and_relative_focus_stops_at_edges() {
        let mut layout = Layout::new(Size::new(1000, 600));
        for window in [A, B, C] {
            layout.insert(window, proportion(600)).unwrap();
        }

        layout.focus(A).unwrap();
        assert_eq!(layout.viewport(), 0);
        assert!(!layout.focus_relative(Direction::Previous));
        assert!(layout.focus_relative(Direction::Next));
        assert_eq!(layout.focused_window(), Some(B));
        assert_eq!(layout.viewport(), 200);
        assert!(layout.focus_relative(Direction::Next));
        assert_eq!(layout.viewport(), 800);
        assert!(!layout.focus_relative(Direction::Next));
    }

    #[test]
    fn moving_columns_preserves_focus_and_updates_visibility() {
        let mut layout = Layout::new(Size::new(1000, 600));
        for window in [A, B, C] {
            layout.insert(window, proportion(500)).unwrap();
        }

        layout.focus(B).unwrap();
        assert!(layout.move_focused(Direction::Previous));
        assert_eq!(windows(&layout, MAIN), alloc::vec![B, A, C]);
        assert_eq!(layout.focused_window(), Some(B));
        assert!(!layout.move_focused(Direction::Previous));

        layout.move_window(B, 2).unwrap();
        assert_eq!(windows(&layout, MAIN), alloc::vec![A, C, B]);
        assert_eq!(layout.focused_window(), Some(B));
        assert_eq!(layout.viewport(), 500);
        assert_eq!(
            layout.move_window(B, 3),
            Err(LayoutError::InvalidColumnIndex)
        );
    }

    #[test]
    fn width_changes_reflow_columns_and_keep_focus_visible() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, Proportion::HALF).unwrap();
        layout.insert(B, Proportion::HALF).unwrap();
        layout.set_width(A, proportion(750)).unwrap();

        assert_eq!(layout.viewport(), 250);
        let placements = layout.placements();
        assert_eq!(placements[0].outer, Rect::new(-250, 0, 750, 600));
        assert_eq!(placements[1].outer, Rect::new(500, 0, 500, 600));
        assert_eq!(layout.columns(MAIN).unwrap()[0].width, proportion(750));
    }

    #[test]
    fn incremental_width_adjustment_crosses_full_width_and_saturates() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(400)).unwrap();

        layout.adjust_width(A, 600).unwrap();
        assert_eq!(layout.columns(MAIN).unwrap()[0].width, Proportion::FULL);
        assert_eq!(layout.placements()[0].outer.width, 1000);

        layout.adjust_width(A, 250).unwrap();
        assert_eq!(layout.columns(MAIN).unwrap()[0].width, proportion(1250));
        assert_eq!(layout.placements()[0].outer.width, 1250);

        layout.adjust_width(A, i32::MAX).unwrap();
        assert_eq!(layout.columns(MAIN).unwrap()[0].width.per_mille(), u16::MAX);
        layout.adjust_width(A, i32::MIN).unwrap();
        assert_eq!(layout.columns(MAIN).unwrap()[0].width.per_mille(), 1);
        assert_eq!(layout.adjust_width(B, 100), Err(LayoutError::UnknownWindow));
    }

    #[test]
    fn aligns_a_lone_narrow_column_left_center_and_right() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(400)).unwrap();

        assert!(layout.align_focused(HorizontalAlignment::Left));
        assert_eq!(layout.viewport(), 0);
        assert_eq!(layout.placements()[0].outer.x, 0);

        assert!(layout.align_focused(HorizontalAlignment::Center));
        assert_eq!(layout.viewport(), -300);
        assert_eq!(layout.placements()[0].outer.x, 300);

        assert!(layout.align_focused(HorizontalAlignment::Right));
        assert_eq!(layout.viewport(), -600);
        assert_eq!(layout.placements()[0].outer.x, 600);
    }

    #[test]
    fn aligns_full_width_and_oversized_columns() {
        let mut full = Layout::new(Size::new(1000, 600));
        full.insert(A, Proportion::FULL).unwrap();
        for alignment in [
            HorizontalAlignment::Left,
            HorizontalAlignment::Center,
            HorizontalAlignment::Right,
        ] {
            assert!(full.align_focused(alignment));
            assert_eq!(full.viewport(), 0);
            assert_eq!(full.placements()[0].outer, Rect::new(0, 0, 1000, 600));
        }

        let mut oversized = Layout::new(Size::new(1000, 600));
        oversized.insert(A, proportion(1500)).unwrap();
        assert!(oversized.align_focused(HorizontalAlignment::Left));
        assert_eq!(oversized.viewport(), 0);
        assert_eq!(oversized.placements()[0].outer.x, 0);
        assert!(oversized.align_focused(HorizontalAlignment::Center));
        assert_eq!(oversized.viewport(), 250);
        assert_eq!(oversized.placements()[0].outer.x, -250);
        assert!(oversized.align_focused(HorizontalAlignment::Right));
        assert_eq!(oversized.viewport(), 500);
        assert_eq!(oversized.placements()[0].outer.x, -500);
    }

    #[test]
    fn endpoint_overscroll_aligns_first_and_final_columns() {
        let mut layout = Layout::new(Size::new(1000, 600));
        for window in [A, B, C] {
            layout.insert(window, proportion(400)).unwrap();
        }

        layout.focus(A).unwrap();
        assert!(layout.align_focused(HorizontalAlignment::Right));
        assert_eq!(layout.viewport(), -600);
        assert_eq!(layout.placements()[0].outer.x, 600);

        layout.focus(C).unwrap();
        assert!(layout.align_focused(HorizontalAlignment::Left));
        assert_eq!(layout.viewport(), 800);
        assert_eq!(layout.placements()[2].outer.x, 0);
        assert!(layout.align_focused(HorizontalAlignment::Center));
        assert_eq!(layout.viewport(), 500);
        assert_eq!(layout.placements()[2].outer.x, 300);
        assert!(layout.align_focused(HorizontalAlignment::Right));
        assert_eq!(layout.viewport(), 200);
        assert_eq!(layout.placements()[2].outer.x, 600);

        let mut oversized = Layout::new(Size::new(1000, 600));
        oversized.insert(A, proportion(1500)).unwrap();
        oversized.insert(B, proportion(1500)).unwrap();
        oversized.focus(A).unwrap();
        assert!(oversized.align_focused(HorizontalAlignment::Right));
        assert_eq!(oversized.viewport(), 500);
        assert_eq!(oversized.placements()[0].outer.x, -500);
        oversized.focus(B).unwrap();
        assert!(oversized.align_focused(HorizontalAlignment::Left));
        assert_eq!(oversized.viewport(), 1500);
        assert_eq!(oversized.placements()[1].outer.x, 0);
        assert!(oversized.align_focused(HorizontalAlignment::Right));
        assert_eq!(oversized.viewport(), 2000);
        assert_eq!(oversized.placements()[1].outer.x, -500);

        let mut empty = Layout::new(Size::new(1000, 600));
        assert!(!empty.align_focused(HorizontalAlignment::Center));
    }

    #[test]
    fn removal_selects_a_neighbour_and_rejects_duplicates() {
        let mut layout = Layout::new(Size::new(1000, 600));
        for window in [A, B, C] {
            layout.insert(window, proportion(400)).unwrap();
        }
        assert_eq!(
            layout.insert(A, proportion(400)),
            Err(LayoutError::DuplicateWindow)
        );

        layout.focus(B).unwrap();
        assert_eq!(layout.remove(B).unwrap().window, B);
        assert_eq!(windows(&layout, MAIN), alloc::vec![A, C]);
        assert_eq!(layout.focused_window(), Some(C));
        layout.remove(C).unwrap();
        assert_eq!(layout.focused_window(), Some(A));
        layout.remove(A).unwrap();
        assert_eq!(layout.focused_window(), None);
        assert_eq!(layout.viewport(), 0);
        assert_eq!(layout.remove(A), Err(LayoutError::UnknownWindow));
    }

    #[test]
    fn placements_clip_outer_rectangles_and_apply_client_insets() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.set_decorations(Insets::new(10, 20, 30, 40));
        layout.insert(A, proportion(600)).unwrap();
        layout.insert(B, proportion(600)).unwrap();

        let placements = layout.placements();
        assert_eq!(layout.viewport(), 200);
        assert_eq!(placements[0].outer, Rect::new(-200, 0, 600, 600));
        assert_eq!(placements[0].client, Rect::new(-190, 20, 560, 540));
        assert_eq!(placements[0].visible, Some(Rect::new(0, 0, 400, 600)));
        assert_eq!(placements[1].outer, Rect::new(400, 0, 600, 600));
        assert_eq!(placements[1].client, Rect::new(410, 20, 560, 540));
        assert!(placements[1].focused);
    }

    #[test]
    fn oversized_insets_saturate_client_geometry() {
        let mut layout = Layout::new(Size::new(100, 50));
        layout.set_decorations(Insets::new(80, 40, 80, 40));
        layout.insert(A, Proportion::FULL).unwrap();

        assert_eq!(layout.placements()[0].client, Rect::new(80, 40, 0, 0));
    }

    #[test]
    fn fullscreen_exit_restores_position_width_focus_and_viewport() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.set_decorations(Insets::new(5, 6, 7, 8));
        layout.insert(A, proportion(400)).unwrap();
        layout.insert(B, proportion(700)).unwrap();
        layout.insert(C, proportion(600)).unwrap();
        layout.focus(B).unwrap();
        assert_eq!(layout.viewport(), 400);

        layout.enter_fullscreen(B).unwrap();
        assert!(layout.is_fullscreen());
        assert_eq!(layout.fullscreen_window(), Some(B));
        assert_eq!(windows(&layout, MAIN), alloc::vec![B, A, C]);
        assert_eq!(layout.columns(MAIN).unwrap()[0].width, Proportion::FULL);
        assert_eq!(layout.viewport(), 0);
        assert_eq!(
            layout.placements(),
            alloc::vec![Placement {
                window: B,
                outer: Rect::new(0, 0, 1000, 600),
                client: Rect::new(0, 0, 1000, 600),
                visible: Some(Rect::new(0, 0, 1000, 600)),
                focused: true,
            }]
        );

        assert!(layout.exit_fullscreen());
        assert!(!layout.exit_fullscreen());
        assert_eq!(windows(&layout, MAIN), alloc::vec![A, B, C]);
        assert_eq!(layout.columns(MAIN).unwrap()[1].width, proportion(700));
        assert_eq!(layout.focused_window(), Some(B));
        assert_eq!(layout.viewport(), 400);
    }

    #[test]
    fn normal_mutation_exits_fullscreen_before_applying_the_change() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(400)).unwrap();
        layout.insert(B, proportion(600)).unwrap();
        layout.enter_fullscreen(A).unwrap();

        layout.set_width(A, proportion(300)).unwrap();
        assert!(!layout.is_fullscreen());
        assert_eq!(windows(&layout, MAIN), alloc::vec![A, B]);
        assert_eq!(layout.columns(MAIN).unwrap()[0].width, proportion(300));

        layout.enter_fullscreen(A).unwrap();
        layout.remove(A).unwrap();
        assert!(!layout.is_fullscreen());
        assert_eq!(windows(&layout, MAIN), alloc::vec![B]);
    }

    #[test]
    fn fullscreen_relative_focus_uses_the_fullscreen_column_and_stays_at_edges() {
        let mut layout = Layout::new(Size::new(1000, 600));
        for window in [A, B, C] {
            layout.insert(window, proportion(400)).unwrap();
        }
        layout.focus(A).unwrap();
        layout.enter_fullscreen(C).unwrap();

        assert!(!layout.focus_relative(Direction::Next));
        assert_eq!(layout.fullscreen_window(), Some(C));
        layout.focus(C).unwrap();
        assert_eq!(layout.fullscreen_window(), Some(C));

        assert!(layout.focus_relative(Direction::Previous));
        assert!(!layout.is_fullscreen());
        assert_eq!(layout.focused_window(), Some(B));

        layout.focus(A).unwrap();
        layout.enter_fullscreen(C).unwrap();
        assert!(layout.move_focused(Direction::Previous));
        assert!(!layout.is_fullscreen());
        assert_eq!(windows(&layout, MAIN), alloc::vec![A, C, B]);
        assert_eq!(layout.focused_window(), Some(C));

        layout.move_window(C, 2).unwrap();
        layout.enter_fullscreen(A).unwrap();
        assert!(!layout.focus_relative(Direction::Previous));
        assert!(!layout.move_focused(Direction::Previous));
        assert_eq!(layout.fullscreen_window(), Some(A));
    }

    #[test]
    fn alignment_exits_fullscreen_and_targets_the_fullscreen_column() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(400)).unwrap();
        layout.insert(B, proportion(400)).unwrap();
        layout.focus(A).unwrap();
        layout.enter_fullscreen(B).unwrap();

        assert!(layout.align_focused(HorizontalAlignment::Left));
        assert!(!layout.is_fullscreen());
        assert_eq!(layout.focused_window(), Some(B));
        assert_eq!(layout.placements()[1].outer.x, 0);
    }

    #[test]
    fn fullscreen_restore_scales_focus_viewport_and_endpoint_overscroll() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(400)).unwrap();
        layout.insert(B, proportion(700)).unwrap();
        layout.insert(C, proportion(600)).unwrap();
        layout.focus(B).unwrap();
        assert_eq!(layout.viewport(), 400);
        layout.enter_fullscreen(B).unwrap();

        layout.set_output_size(Size::new(500, 300));
        assert!(layout.exit_fullscreen());
        assert_eq!(layout.focused_window(), Some(B));
        assert_eq!(layout.viewport(), 200);
        let placements = layout.placements();
        assert_eq!(placements[0].outer, Rect::new(-200, 0, 200, 300));
        assert_eq!(placements[1].outer, Rect::new(0, 0, 350, 300));
        assert_eq!(placements[2].outer, Rect::new(350, 0, 300, 300));

        layout.focus(A).unwrap();
        assert!(layout.align_focused(HorizontalAlignment::Right));
        assert_eq!(layout.viewport(), -300);
        layout.enter_fullscreen(C).unwrap();
        layout.set_output_size(Size::new(1000, 600));
        assert!(layout.exit_fullscreen());
        assert_eq!(layout.focused_window(), Some(A));
        assert_eq!(layout.viewport(), -600);
        assert_eq!(layout.placements()[0].outer.x, 600);
    }

    #[test]
    fn workspaces_keep_independent_columns_focus_and_viewports() {
        let mut layout = Layout::with_workspace(Size::new(1000, 600), MAIN);
        layout.insert(A, proportion(700)).unwrap();
        layout.insert(B, proportion(700)).unwrap();
        assert_eq!(layout.viewport(), 400);

        layout.add_workspace(OTHER).unwrap();
        layout.set_active_workspace(OTHER).unwrap();
        layout.insert(C, Proportion::HALF).unwrap();
        layout.insert(D, Proportion::HALF).unwrap();
        assert_eq!(layout.viewport(), 0);
        assert_eq!(layout.focused_window(), Some(D));
        assert_eq!(
            layout.workspace_ids().collect::<Vec<_>>(),
            alloc::vec![MAIN, OTHER]
        );

        layout.focus(A).unwrap();
        assert_eq!(layout.active_workspace(), MAIN);
        assert_eq!(layout.viewport(), 0);
        assert_eq!(layout.focused_window_in(OTHER).unwrap(), Some(D));
        assert_eq!(windows(&layout, OTHER), alloc::vec![C, D]);
        assert_eq!(
            layout.insert(C, Proportion::HALF),
            Err(LayoutError::DuplicateWindow)
        );
    }

    #[test]
    fn workspace_removal_keeps_a_valid_active_workspace() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.add_workspace(OTHER).unwrap();
        layout.set_active_workspace(OTHER).unwrap();
        layout.remove_workspace(OTHER).unwrap();
        assert_eq!(layout.active_workspace(), MAIN);
        assert_eq!(layout.workspace_count(), 1);
        assert_eq!(
            layout.remove_workspace(MAIN),
            Err(LayoutError::LastWorkspace)
        );
    }

    #[test]
    fn output_resize_recomputes_widths_and_visibility() {
        let mut layout = Layout::new(Size::new(1000, 600));
        layout.insert(A, proportion(600)).unwrap();
        layout.insert(B, proportion(600)).unwrap();
        assert_eq!(layout.viewport(), 200);

        layout.set_output_size(Size::new(500, 300));
        assert_eq!(layout.viewport(), 100);
        let placements = layout.placements();
        assert_eq!(placements[0].outer, Rect::new(-100, 0, 300, 300));
        assert_eq!(placements[1].outer, Rect::new(200, 0, 300, 300));
    }

    #[test]
    fn output_resize_preserves_center_and_endpoint_alignment() {
        let mut layout = Layout::new(Size::new(1000, 600));
        for window in [A, B, C] {
            layout.insert(window, proportion(400)).unwrap();
        }

        layout.focus(A).unwrap();
        assert!(layout.align_focused(HorizontalAlignment::Center));
        layout.set_output_size(Size::new(500, 300));
        assert_eq!(layout.viewport(), -150);
        assert_eq!(layout.placements()[0].outer, Rect::new(150, 0, 200, 300));

        layout.focus(C).unwrap();
        assert!(layout.align_focused(HorizontalAlignment::Left));
        assert_eq!(layout.viewport(), 400);
        layout.set_output_size(Size::new(1000, 600));
        assert_eq!(layout.viewport(), 800);
        assert_eq!(layout.placements()[2].outer, Rect::new(0, 0, 400, 600));
    }
}
