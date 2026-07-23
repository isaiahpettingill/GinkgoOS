#![no_std]

//! Bounded, platform-independent editing state for GinkgoOS text editors.
//!
//! Cursor and selection positions are byte offsets, and are always valid UTF-8
//! character boundaries. The model performs no I/O and has no platform
//! dependencies, making it suitable for both graphical `no_std` applications
//! and host-side tests.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use core::ops::Range;
use core::str;

/// Maximum document length in UTF-8 bytes (256 KiB).
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
/// Maximum number of snapshots retained in each undo and redo history.
pub const MAX_HISTORY_SNAPSHOTS: usize = 64;
/// Maximum text bytes retained by either history queue.
pub const MAX_HISTORY_BYTES: usize = 384 * 1024;

/// An error produced while loading or changing document text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentError {
    /// Input bytes were not valid UTF-8.
    InvalidUtf8,
    /// The resulting document would exceed [`MAX_DOCUMENT_BYTES`].
    TooLarge { size: usize, max: usize },
}

#[derive(Clone, Debug)]
struct Snapshot {
    text: String,
    cursor: usize,
    selection_anchor: Option<usize>,
    revision: u64,
}

/// A bounded plain-text document with cursor, selection, and edit history.
#[derive(Clone, Debug)]
pub struct Document {
    text: String,
    cursor: usize,
    selection_anchor: Option<usize>,
    preferred_column: Option<usize>,
    revision: u64,
    saved_revision: u64,
    next_revision: u64,
    undo: VecDeque<Snapshot>,
    redo: VecDeque<Snapshot>,
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

impl Document {
    /// Creates an empty, clean document.
    pub const fn new() -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            selection_anchor: None,
            preferred_column: None,
            revision: 0,
            saved_revision: 0,
            next_revision: 1,
            undo: VecDeque::new(),
            redo: VecDeque::new(),
        }
    }

    /// Loads a clean document from UTF-8 bytes.
    pub fn load(bytes: &[u8]) -> Result<Self, DocumentError> {
        let mut document = Self::new();
        document.reset(bytes)?;
        Ok(document)
    }

    /// Replaces all content from UTF-8 bytes and clears history and dirty state.
    ///
    /// On error, the document is left unchanged.
    pub fn reset(&mut self, bytes: &[u8]) -> Result<(), DocumentError> {
        Self::check_size(bytes.len())?;
        let text = str::from_utf8(bytes).map_err(|_| DocumentError::InvalidUtf8)?;

        self.text = String::from(text);
        self.cursor = 0;
        self.selection_anchor = None;
        self.preferred_column = None;
        self.revision = 0;
        self.saved_revision = 0;
        self.next_revision = 1;
        self.undo.clear();
        self.redo.clear();
        Ok(())
    }

    /// Returns the complete document text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the document length in UTF-8 bytes.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns whether the document is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Returns the cursor as a UTF-8 byte offset.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Returns the selection anchor as a UTF-8 byte offset, when selected.
    pub fn selection_anchor(&self) -> Option<usize> {
        self.selection_anchor
    }

    /// Returns the selected byte range in ascending order.
    pub fn selection_range(&self) -> Option<Range<usize>> {
        self.selection_anchor.map(|anchor| {
            if anchor < self.cursor {
                anchor..self.cursor
            } else {
                self.cursor..anchor
            }
        })
    }

    /// Returns whether there is a non-empty selection.
    pub fn has_selection(&self) -> bool {
        self.selection_anchor.is_some()
    }

    /// Returns the selected text for copying or cutting.
    pub fn selected_text(&self) -> Option<&str> {
        self.selection_range().map(|range| &self.text[range])
    }

    /// Returns whether content differs from the last loaded, reset, or saved revision.
    pub fn is_dirty(&self) -> bool {
        self.revision != self.saved_revision
    }

    /// Marks the current content revision as saved.
    pub fn mark_saved(&mut self) {
        self.saved_revision = self.revision;
    }

    /// Returns whether an undo snapshot is available.
    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    /// Returns whether a redo snapshot is available.
    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Inserts text at the cursor, replacing any selection.
    pub fn insert_text(&mut self, text: &str) -> Result<bool, DocumentError> {
        self.replace_selection(text)
    }

    /// Inserts a newline at the cursor, replacing any selection.
    pub fn insert_newline(&mut self) -> Result<bool, DocumentError> {
        self.replace_selection("\n")
    }

    /// Replaces the selection with text, or inserts at the cursor if unselected.
    pub fn replace_selection(&mut self, replacement: &str) -> Result<bool, DocumentError> {
        let range = self.selection_range().unwrap_or(self.cursor..self.cursor);
        let resulting_size = self.text.len() - range.len() + replacement.len();
        Self::check_size(resulting_size)?;

        if &self.text[range.clone()] == replacement {
            self.cursor = range.start + replacement.len();
            self.selection_anchor = None;
            self.preferred_column = None;
            return Ok(false);
        }

        self.begin_edit();
        self.text.replace_range(range.clone(), replacement);
        self.cursor = range.start + replacement.len();
        self.selection_anchor = None;
        self.preferred_column = None;
        self.finish_edit();
        Ok(true)
    }

    /// Deletes the selection. Returns `false` when no text was selected.
    pub fn delete_selection(&mut self) -> bool {
        if !self.has_selection() {
            return false;
        }
        self.replace_selection("")
            .expect("deleting text cannot exceed the document limit")
    }

    /// Deletes the previous word or punctuation run, including leading whitespace.
    pub fn delete_word_backward(&mut self) -> bool {
        if self.delete_selection() {
            return true;
        }
        if self.cursor == 0 {
            return false;
        }

        let end = self.cursor;
        let mut start = end;
        while let Some((index, character)) = self.text[..start].char_indices().next_back() {
            if !character.is_whitespace() {
                break;
            }
            start = index;
        }
        let Some((_, previous)) = self.text[..start].char_indices().next_back() else {
            self.selection_anchor = Some(0);
            return self.delete_selection();
        };
        let previous_is_word = previous.is_alphanumeric() || previous == '_';
        while let Some((index, character)) = self.text[..start].char_indices().next_back() {
            let is_word = character.is_alphanumeric() || character == '_';
            if character.is_whitespace() || is_word != previous_is_word {
                break;
            }
            start = index;
        }
        self.cursor = end;
        self.selection_anchor = Some(start);
        self.delete_selection()
    }

    /// Deletes the character before the cursor, or the current selection.
    pub fn backspace(&mut self) -> bool {
        if self.delete_selection() {
            return true;
        }
        if self.cursor == 0 {
            return false;
        }

        let start = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(index, _)| index);
        self.selection_anchor = Some(start);
        self.delete_selection()
    }

    /// Deletes the character after the cursor, or the current selection.
    pub fn delete(&mut self) -> bool {
        if self.delete_selection() {
            return true;
        }
        if self.cursor == self.text.len() {
            return false;
        }

        let end = self.cursor
            + self.text[self.cursor..]
                .chars()
                .next()
                .expect("cursor before end has a character")
                .len_utf8();
        self.selection_anchor = Some(end);
        self.delete_selection()
    }

    /// Moves left by one Unicode scalar value.
    pub fn move_left(&mut self, select: bool) -> bool {
        self.preferred_column = None;
        if !select {
            if let Some(range) = self.selection_range() {
                return self.set_cursor(range.start, false);
            }
        }
        let target = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(self.cursor, |(index, _)| index);
        self.set_cursor(target, select)
    }

    /// Moves right by one Unicode scalar value.
    pub fn move_right(&mut self, select: bool) -> bool {
        self.preferred_column = None;
        if !select {
            if let Some(range) = self.selection_range() {
                return self.set_cursor(range.end, false);
            }
        }
        let target = self.text[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |character| self.cursor + character.len_utf8());
        self.set_cursor(target, select)
    }

    /// Moves to the previous line while preserving the desired character column.
    pub fn move_up(&mut self, select: bool) -> bool {
        let line_start = self.line_start(self.cursor);
        let column = self
            .preferred_column
            .unwrap_or_else(|| self.text[line_start..self.cursor].chars().count());
        self.preferred_column = Some(column);

        let target = if line_start == 0 {
            self.cursor
        } else {
            let previous_end = line_start - 1;
            let previous_start = self.line_start(previous_end);
            self.byte_at_column(previous_start, previous_end, column)
        };
        self.set_cursor(target, select)
    }

    /// Moves to the next line while preserving the desired character column.
    pub fn move_down(&mut self, select: bool) -> bool {
        let line_end = self.line_end(self.cursor);
        let line_start = self.line_start(self.cursor);
        let column = self
            .preferred_column
            .unwrap_or_else(|| self.text[line_start..self.cursor].chars().count());
        self.preferred_column = Some(column);

        let target = if line_end == self.text.len() {
            self.cursor
        } else {
            let next_start = line_end + 1;
            let next_end = self.line_end(next_start);
            self.byte_at_column(next_start, next_end, column)
        };
        self.set_cursor(target, select)
    }

    /// Moves to the start of the current line.
    pub fn move_home(&mut self, select: bool) -> bool {
        self.preferred_column = None;
        self.set_cursor(self.line_start(self.cursor), select)
    }

    /// Moves to the end of the current line, before its newline.
    pub fn move_end(&mut self, select: bool) -> bool {
        self.preferred_column = None;
        self.set_cursor(self.line_end(self.cursor), select)
    }

    /// Selects the entire document.
    pub fn select_all(&mut self) {
        self.preferred_column = None;
        if self.text.is_empty() {
            self.cursor = 0;
            self.selection_anchor = None;
        } else {
            self.selection_anchor = Some(0);
            self.cursor = self.text.len();
        }
    }

    /// Restores the most recent undo snapshot.
    pub fn undo(&mut self) -> bool {
        let Some(snapshot) = self.undo.pop_back() else {
            return false;
        };
        let current = self.snapshot();
        Self::push_bounded(&mut self.redo, current);
        self.restore(snapshot);
        true
    }

    /// Reapplies the most recent undone snapshot.
    pub fn redo(&mut self) -> bool {
        let Some(snapshot) = self.redo.pop_back() else {
            return false;
        };
        let current = self.snapshot();
        Self::push_bounded(&mut self.undo, current);
        self.restore(snapshot);
        true
    }

    fn check_size(size: usize) -> Result<(), DocumentError> {
        if size > MAX_DOCUMENT_BYTES {
            Err(DocumentError::TooLarge {
                size,
                max: MAX_DOCUMENT_BYTES,
            })
        } else {
            Ok(())
        }
    }

    fn begin_edit(&mut self) {
        let snapshot = self.snapshot();
        Self::push_bounded(&mut self.undo, snapshot);
        self.redo.clear();
    }

    fn finish_edit(&mut self) {
        self.revision = self.next_revision;
        self.next_revision = self.next_revision.wrapping_add(1);
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            text: self.text.clone(),
            cursor: self.cursor,
            selection_anchor: self.selection_anchor,
            revision: self.revision,
        }
    }

    fn restore(&mut self, snapshot: Snapshot) {
        self.text = snapshot.text;
        self.cursor = snapshot.cursor;
        self.selection_anchor = snapshot.selection_anchor;
        self.revision = snapshot.revision;
        self.preferred_column = None;
    }

    fn push_bounded(history: &mut VecDeque<Snapshot>, snapshot: Snapshot) {
        let snapshot_bytes = snapshot.text.len();
        let mut history_bytes: usize = history.iter().map(|entry| entry.text.len()).sum();
        while history.len() >= MAX_HISTORY_SNAPSHOTS
            || history_bytes.saturating_add(snapshot_bytes) > MAX_HISTORY_BYTES
        {
            let Some(removed) = history.pop_front() else {
                break;
            };
            history_bytes = history_bytes.saturating_sub(removed.text.len());
        }
        history.push_back(snapshot);
    }

    fn set_cursor(&mut self, target: usize, select: bool) -> bool {
        debug_assert!(self.text.is_char_boundary(target));
        let old_cursor = self.cursor;
        let old_anchor = self.selection_anchor;

        if select && self.selection_anchor.is_none() && target != self.cursor {
            self.selection_anchor = Some(self.cursor);
        } else if !select {
            self.selection_anchor = None;
        }
        self.cursor = target;
        if self.selection_anchor == Some(self.cursor) {
            self.selection_anchor = None;
        }

        self.cursor != old_cursor || self.selection_anchor != old_anchor
    }

    fn line_start(&self, position: usize) -> usize {
        self.text[..position]
            .rfind('\n')
            .map_or(0, |newline| newline + 1)
    }

    fn line_end(&self, position: usize) -> usize {
        self.text[position..]
            .find('\n')
            .map_or(self.text.len(), |offset| position + offset)
    }

    fn byte_at_column(&self, start: usize, end: usize, column: usize) -> usize {
        self.text[start..end]
            .char_indices()
            .nth(column)
            .map_or(end, |(offset, _)| start + offset)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;

    #[test]
    fn utf8_navigation_and_deletion_stay_on_boundaries() {
        let mut document = Document::load("aé文🙂".as_bytes()).unwrap();
        document.move_end(false);

        let expected = [6, 3, 1, 0];
        for position in expected {
            assert!(document.move_left(false));
            assert_eq!(document.cursor(), position);
            assert!(document.text().is_char_boundary(position));
        }

        assert!(document.move_right(false));
        assert_eq!(document.cursor(), 1);
        assert!(document.delete());
        assert_eq!(document.text(), "a文🙂");
        assert!(document.backspace());
        assert_eq!(document.text(), "文🙂");
        assert_eq!(document.cursor(), 0);
    }

    #[test]
    fn selection_can_be_copied_deleted_and_replaced() {
        let mut document = Document::load("one 世界 three".as_bytes()).unwrap();
        document.move_right(false);
        document.move_right(false);
        document.move_right(false);
        document.move_right(false);
        for _ in 0..2 {
            document.move_right(true);
        }

        assert_eq!(document.selected_text(), Some("世界"));
        assert_eq!(document.selection_range(), Some(4..10));
        assert!(document.replace_selection("two").unwrap());
        assert_eq!(document.text(), "one two three");
        assert_eq!(document.cursor(), 7);
        assert!(!document.has_selection());

        document.select_all();
        assert_eq!(document.selected_text(), Some("one two three"));
        assert!(document.delete_selection());
        assert!(document.is_empty());
        assert_eq!(document.cursor(), 0);
    }

    #[test]
    fn typing_replaces_a_backward_shift_selection() {
        let mut document = Document::load("abcd".as_bytes()).unwrap();
        document.move_end(false);
        document.move_left(true);
        document.move_left(true);

        assert_eq!(document.selection_anchor(), Some(4));
        assert_eq!(document.selected_text(), Some("cd"));
        document.insert_text("XY").unwrap();
        assert_eq!(document.text(), "abXY");
        assert_eq!(document.cursor(), 4);
    }

    #[test]
    fn vertical_movement_preserves_character_column() {
        let mut document = Document::load("αβγδε\nx\n12345".as_bytes()).unwrap();
        for _ in 0..4 {
            document.move_right(false);
        }
        assert_eq!(document.cursor(), 8);

        assert!(document.move_down(false));
        assert_eq!(document.cursor(), 12);
        assert!(document.move_down(false));
        assert_eq!(document.cursor(), 17);
        assert!(document.move_up(true));
        assert_eq!(document.selected_text(), Some("\n1234"));
        assert!(document.move_up(true));
        assert_eq!(document.cursor(), 8);
        assert_eq!(document.selected_text(), Some("ε\nx\n1234"));
    }

    #[test]
    fn home_end_and_shift_selection_respect_lines() {
        let mut document = Document::load("first\nsecond\n".as_bytes()).unwrap();
        document.move_down(false);
        document.move_end(false);
        assert_eq!(document.cursor(), 12);
        document.move_home(true);
        assert_eq!(document.selected_text(), Some("second"));
        document.move_home(false);
        assert_eq!(document.cursor(), 6);
        assert!(!document.has_selection());
    }

    #[test]
    fn word_backspace_handles_unicode_whitespace_punctuation_and_selection() {
        let mut document = Document::load("one  κόσμος...  next".as_bytes()).unwrap();
        document.move_end(false);
        assert!(document.delete_word_backward());
        assert_eq!(document.text(), "one  κόσμος...  ");
        assert!(document.delete_word_backward());
        assert_eq!(document.text(), "one  κόσμος");
        assert!(document.delete_word_backward());
        assert_eq!(document.text(), "one  ");

        document.select_all();
        assert!(document.delete_word_backward());
        assert!(document.is_empty());
        assert!(!document.delete_word_backward());
    }

    #[test]
    fn dirty_state_tracks_saved_revision_through_history() {
        let mut document = Document::new();
        assert!(!document.is_dirty());
        document.insert_text("saved").unwrap();
        assert!(document.is_dirty());
        document.mark_saved();
        assert!(!document.is_dirty());

        document.move_left(false);
        assert!(!document.is_dirty());
        document.insert_text("!").unwrap();
        assert!(document.is_dirty());
        assert!(document.undo());
        assert!(!document.is_dirty());
        assert!(document.redo());
        assert!(document.is_dirty());
        document.mark_saved();
        assert!(!document.is_dirty());
    }

    #[test]
    fn undo_redo_are_bounded_and_new_edits_clear_redo() {
        let mut document = Document::new();
        for _ in 0..65 {
            document.insert_text("x").unwrap();
        }

        let mut undos = 0;
        while document.undo() {
            undos += 1;
        }
        assert_eq!(undos, MAX_HISTORY_SNAPSHOTS);
        assert_eq!(document.text(), "x");

        let mut redos = 0;
        while document.redo() {
            redos += 1;
        }
        assert_eq!(redos, MAX_HISTORY_SNAPSHOTS);
        assert_eq!(document.len(), 65);

        assert!(document.undo());
        assert!(document.can_redo());
        document.insert_newline().unwrap();
        assert!(!document.can_redo());
    }

    #[test]
    fn load_and_edits_reject_oversize_without_mutating() {
        let oversized = vec![b'x'; MAX_DOCUMENT_BYTES + 1];
        assert_eq!(
            Document::load(&oversized).unwrap_err(),
            DocumentError::TooLarge {
                size: MAX_DOCUMENT_BYTES + 1,
                max: MAX_DOCUMENT_BYTES,
            }
        );

        let mut document = Document::load(b"keep").unwrap();
        assert_eq!(
            document.insert_text(str::from_utf8(&oversized).unwrap()),
            Err(DocumentError::TooLarge {
                size: MAX_DOCUMENT_BYTES + 5,
                max: MAX_DOCUMENT_BYTES,
            })
        );
        assert_eq!(document.text(), "keep");
        assert!(!document.is_dirty());
    }

    #[test]
    fn invalid_utf8_and_failed_reset_leave_document_unchanged() {
        let invalid = [0xf0, 0x28, 0x8c, 0x28];
        assert!(matches!(
            Document::load(&invalid),
            Err(DocumentError::InvalidUtf8)
        ));

        let mut document = Document::load(b"valid").unwrap();
        assert_eq!(document.reset(&invalid), Err(DocumentError::InvalidUtf8));
        assert_eq!(document.text(), "valid");
        assert!(!document.is_dirty());
    }

    #[test]
    fn exact_capacity_is_accepted_and_snapshots_never_exceed_it() {
        let at_limit = vec![b'a'; MAX_DOCUMENT_BYTES];
        let mut document = Document::load(&at_limit).unwrap();
        document.move_end(false);
        assert_eq!(
            document.insert_text("x"),
            Err(DocumentError::TooLarge {
                size: MAX_DOCUMENT_BYTES + 1,
                max: MAX_DOCUMENT_BYTES,
            })
        );
        assert_eq!(document.len(), MAX_DOCUMENT_BYTES);

        assert!(document.backspace());
        assert_eq!(document.len(), MAX_DOCUMENT_BYTES - 1);
        assert!(document.undo());
        assert_eq!(document.len(), MAX_DOCUMENT_BYTES);
        assert!(document.redo());
        assert_eq!(document.len(), MAX_DOCUMENT_BYTES - 1);
    }
}
