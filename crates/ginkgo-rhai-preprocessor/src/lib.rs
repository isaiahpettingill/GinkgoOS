#![no_std]

//! Token-aware preprocessing for Ginkgo's command-oriented Rhai dialect.
//!
//! The crate deliberately does not depend on Rhai or a Ginkgo runtime. It only
//! translates command and pipeline sugar into ordinary Rhai source while
//! retaining source mappings suitable for remapping parser/runtime diagnostics.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::fmt;

/// How a registered command consumes source following its name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandSyntax {
    /// The command accepts no source arguments and is dispatched by
    /// `__ginkgo_command`.
    NoArguments,
    /// Shell-like whitespace-separated words, with `$(...)` Rhai interpolation.
    ShellArguments,
    /// One or more comma-separated Rhai expressions.
    RhaiExpression,
}

/// A statically-declarable command description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSpec<'a> {
    pub canonical_name: &'a str,
    pub aliases: &'a [&'a str],
    pub syntax: CommandSyntax,
    pub min_args: usize,
    pub max_args: Option<usize>,
}

impl<'a> CommandSpec<'a> {
    /// Construct a command spec. This is `const` so registries can be described
    /// with static slices.
    pub const fn new(
        canonical_name: &'a str,
        aliases: &'a [&'a str],
        syntax: CommandSyntax,
        min_args: usize,
        max_args: Option<usize>,
    ) -> Self {
        Self {
            canonical_name,
            aliases,
            syntax,
            min_args,
            max_args,
        }
    }

    pub const fn no_arguments(canonical_name: &'a str, aliases: &'a [&'a str]) -> Self {
        Self::new(
            canonical_name,
            aliases,
            CommandSyntax::NoArguments,
            0,
            Some(0),
        )
    }

    pub const fn shell(
        canonical_name: &'a str,
        aliases: &'a [&'a str],
        min_args: usize,
        max_args: Option<usize>,
    ) -> Self {
        Self::new(
            canonical_name,
            aliases,
            CommandSyntax::ShellArguments,
            min_args,
            max_args,
        )
    }

    pub const fn expression(
        canonical_name: &'a str,
        aliases: &'a [&'a str],
        min_args: usize,
        max_args: Option<usize>,
    ) -> Self {
        Self::new(
            canonical_name,
            aliases,
            CommandSyntax::RhaiExpression,
            min_args,
            max_args,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError<'a> {
    EmptyName { command_index: usize },
    InvalidName { name: &'a str },
    InvalidArgumentRange { name: &'a str },
    DuplicateCanonicalName { name: &'a str },
    DuplicateAlias { alias: &'a str },
    NameAliasCollision { name: &'a str },
}

impl fmt::Display for RegistryError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName { command_index } => {
                write!(f, "command {} has an empty canonical name", command_index)
            }
            Self::InvalidName { name } => write!(f, "`{name}` is not a valid command name"),
            Self::InvalidArgumentRange { name } => {
                write!(f, "command `{name}` has an invalid argument range")
            }
            Self::DuplicateCanonicalName { name } => {
                write!(f, "duplicate canonical command name `{name}`")
            }
            Self::DuplicateAlias { alias } => write!(f, "duplicate command alias `{alias}`"),
            Self::NameAliasCollision { name } => {
                write!(f, "command name/alias collision for `{name}`")
            }
        }
    }
}

/// A validated, allocation-free view of command specifications.
#[derive(Clone, Copy, Debug)]
pub struct CommandRegistry<'a> {
    specs: &'a [CommandSpec<'a>],
}

impl<'a> CommandRegistry<'a> {
    pub fn new(specs: &'a [CommandSpec<'a>]) -> Result<Self, RegistryError<'a>> {
        for (index, spec) in specs.iter().enumerate() {
            if spec.canonical_name.is_empty() {
                return Err(RegistryError::EmptyName {
                    command_index: index,
                });
            }
            if !valid_name(spec.canonical_name) {
                return Err(RegistryError::InvalidName {
                    name: spec.canonical_name,
                });
            }
            if spec.max_args.is_some_and(|maximum| maximum < spec.min_args)
                || (spec.syntax == CommandSyntax::NoArguments
                    && (spec.min_args != 0 || spec.max_args != Some(0)))
            {
                return Err(RegistryError::InvalidArgumentRange {
                    name: spec.canonical_name,
                });
            }
            for alias in spec.aliases {
                if !valid_name(alias) {
                    return Err(RegistryError::InvalidName { name: alias });
                }
            }
        }

        for (left_index, left) in specs.iter().enumerate() {
            for right in &specs[left_index + 1..] {
                if left.canonical_name == right.canonical_name {
                    return Err(RegistryError::DuplicateCanonicalName {
                        name: left.canonical_name,
                    });
                }
            }
            for (alias_index, alias) in left.aliases.iter().enumerate() {
                if *alias == left.canonical_name {
                    return Err(RegistryError::NameAliasCollision { name: alias });
                }
                for other in &left.aliases[alias_index + 1..] {
                    if alias == other {
                        return Err(RegistryError::DuplicateAlias { alias });
                    }
                }
                for (right_index, right) in specs.iter().enumerate() {
                    if *alias == right.canonical_name {
                        return Err(RegistryError::NameAliasCollision { name: alias });
                    }
                    for other in right.aliases {
                        if (left_index != right_index || alias.as_ptr() != other.as_ptr())
                            && alias == other
                        {
                            return Err(RegistryError::DuplicateAlias { alias });
                        }
                    }
                }
            }
        }
        Ok(Self { specs })
    }

    pub const fn specs(&self) -> &'a [CommandSpec<'a>] {
        self.specs
    }

    /// Resolve either a canonical name or alias to its command specification.
    pub fn resolve(&self, name: &str) -> Option<&'a CommandSpec<'a>> {
        self.specs
            .iter()
            .find(|spec| spec.canonical_name == name || spec.aliases.contains(&name))
    }

    pub fn preprocess(&self, source: &str) -> Result<PreprocessedSource, PreprocessError> {
        preprocess_with_registry(source, self)
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c == '-' || c.is_ascii_alphanumeric())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceMapping {
    pub generated: SourceSpan,
    pub original: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessedSource {
    pub source: String,
    pub mappings: Vec<SourceMapping>,
}

impl PreprocessedSource {
    /// Map a generated byte offset to the corresponding original span. For a
    /// rewritten range this intentionally returns the whole originating span.
    pub fn original_span(&self, generated_offset: usize) -> Option<SourceSpan> {
        self.mappings
            .iter()
            .filter(|mapping| {
                mapping.generated.start <= generated_offset
                    && generated_offset < mapping.generated.end
            })
            .min_by_key(|mapping| mapping.generated.end - mapping.generated.start)
            .map(|mapping| mapping.original)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreprocessErrorKind {
    UnterminatedString,
    UnterminatedRawString,
    UnterminatedBlockComment,
    UnterminatedInterpolation,
    InvalidEscape,
    MissingExecutableTarget,
    InvalidExecutableTarget,
    ExecutablePipelineUnsupported,
    InvalidPipelineStage,
    TooFewArguments,
    TooManyArguments,
    UnexpectedArguments,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreprocessError {
    pub kind: PreprocessErrorKind,
    pub offset: usize,
    /// One-based line number.
    pub line: usize,
    /// One-based Unicode-scalar column number.
    pub column: usize,
    pub message: String,
}

impl fmt::Display for PreprocessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}:{}", self.message, self.line, self.column)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Ident,
    Space,
    Newline,
    Comment,
    Literal,
    MapOpen,
    Open(char),
    Close(char),
    Pipe,
    At,
    Semicolon,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

fn error(
    source: &str,
    offset: usize,
    kind: PreprocessErrorKind,
    message: String,
) -> PreprocessError {
    let safe_offset = offset.min(source.len());
    let prefix = &source[..safe_offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, tail)| tail)
        .chars()
        .count()
        + 1;
    PreprocessError {
        kind,
        offset: safe_offset,
        line,
        column,
        message,
    }
}

fn lex(source: &str) -> Result<Vec<Token>, PreprocessError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        match bytes[index] {
            b' ' | b'\t' | b'\r' => {
                index += 1;
                while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r') {
                    index += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Space,
                    start,
                    end: index,
                });
            }
            b'\n' => {
                index += 1;
                tokens.push(Token {
                    kind: TokenKind::Newline,
                    start,
                    end: index,
                });
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Comment,
                    start,
                    end: index,
                });
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut depth = 1usize;
                while index < bytes.len() && depth != 0 {
                    if bytes.get(index..index + 2) == Some(b"/*") {
                        depth += 1;
                        index += 2;
                    } else if bytes.get(index..index + 2) == Some(b"*/") {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                if depth != 0 {
                    return Err(error(
                        source,
                        start,
                        PreprocessErrorKind::UnterminatedBlockComment,
                        "unterminated block comment".into(),
                    ));
                }
                tokens.push(Token {
                    kind: TokenKind::Comment,
                    start,
                    end: index,
                });
            }
            b'r' if raw_prefix(bytes, index).is_some() => {
                let hashes = raw_prefix(bytes, index).unwrap();
                index += 2 + hashes;
                loop {
                    if index >= bytes.len() {
                        return Err(error(
                            source,
                            start,
                            PreprocessErrorKind::UnterminatedRawString,
                            "unterminated raw string".into(),
                        ));
                    }
                    if bytes[index] == b'"'
                        && bytes
                            .get(index + 1..index + 1 + hashes)
                            .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                    {
                        index += 1 + hashes;
                        break;
                    }
                    index += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Literal,
                    start,
                    end: index,
                });
            }
            quote @ (b'"' | b'\'' | b'`') if !preceded_by_escape(bytes, index) => {
                index += 1;
                let mut escaped = false;
                let mut closed = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == quote {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(error(
                        source,
                        start,
                        PreprocessErrorKind::UnterminatedString,
                        "unterminated string literal".into(),
                    ));
                }
                tokens.push(Token {
                    kind: TokenKind::Literal,
                    start,
                    end: index,
                });
            }
            b'|' if bytes.get(index + 1) == Some(&b'>') => {
                index += 2;
                tokens.push(Token {
                    kind: TokenKind::Pipe,
                    start,
                    end: index,
                });
            }
            b';' => {
                index += 1;
                tokens.push(Token {
                    kind: TokenKind::Semicolon,
                    start,
                    end: index,
                });
            }
            b'@' => {
                index += 1;
                tokens.push(Token {
                    kind: TokenKind::At,
                    start,
                    end: index,
                });
            }
            b'#' if bytes.get(index + 1) == Some(&b'{') => {
                index += 2;
                tokens.push(Token {
                    kind: TokenKind::MapOpen,
                    start,
                    end: index,
                });
            }
            byte @ (b'(' | b'[' | b'{') => {
                index += 1;
                tokens.push(Token {
                    kind: TokenKind::Open(byte as char),
                    start,
                    end: index,
                });
            }
            byte @ (b')' | b']' | b'}') => {
                index += 1;
                tokens.push(Token {
                    kind: TokenKind::Close(byte as char),
                    start,
                    end: index,
                });
            }
            byte if is_ident_start(byte) => {
                index += 1;
                while index < bytes.len() && is_ident_continue(bytes[index]) {
                    index += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Ident,
                    start,
                    end: index,
                });
            }
            _ => {
                let ch_len = source[index..].chars().next().unwrap().len_utf8();
                index += ch_len;
                tokens.push(Token {
                    kind: TokenKind::Other,
                    start,
                    end: index,
                });
            }
        }
    }
    Ok(tokens)
}

fn preceded_by_escape(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index;
    let mut backslashes = 0;
    while cursor != 0 && bytes[cursor - 1] == b'\\' {
        cursor -= 1;
        backslashes += 1;
    }
    backslashes % 2 == 1
}

fn raw_prefix(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    let mut cursor = index + 1;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some(cursor - index - 1)
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic() || byte >= 0x80
}
fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit() || byte == b'-'
}
fn trivia(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Space | TokenKind::Newline | TokenKind::Comment
    )
}

struct Rewrite {
    source: String,
    interpolations: Vec<SourceSpan>,
    mappings: Vec<SourceMapping>,
}

impl From<&str> for Rewrite {
    fn from(source: &str) -> Self {
        Self {
            source: source.into(),
            interpolations: Vec::new(),
            mappings: Vec::new(),
        }
    }
}

impl From<String> for Rewrite {
    fn from(source: String) -> Self {
        Self {
            source,
            interpolations: Vec::new(),
            mappings: Vec::new(),
        }
    }
}

struct ShellWords {
    words: Vec<String>,
    interpolations: Vec<SourceSpan>,
}

struct Output {
    source: String,
    mappings: Vec<SourceMapping>,
}

impl Output {
    fn append(&mut self, text: &str, original: SourceSpan) {
        if text.is_empty() {
            return;
        }
        let start = self.source.len();
        self.source.push_str(text);
        self.mappings.push(SourceMapping {
            generated: SourceSpan {
                start,
                end: self.source.len(),
            },
            original,
        });
    }

    fn append_rewrite(&mut self, original_source: &str, rewrite: Rewrite, original: SourceSpan) {
        let generated_start = self.source.len();
        self.append(&rewrite.source, original);
        for mapping in &rewrite.mappings {
            self.mappings.push(SourceMapping {
                generated: SourceSpan {
                    start: generated_start + mapping.generated.start,
                    end: generated_start + mapping.generated.end,
                },
                original: mapping.original,
            });
        }
        let mut search_start = 0;
        for expression in rewrite.interpolations {
            let expression_text = &original_source[expression.start..expression.end];
            let wrapper = format!("({expression_text})");
            let relative_wrapper = rewrite.source[search_start..]
                .find(&wrapper)
                .expect("generated interpolation must retain its raw expression");
            let relative_start = search_start + relative_wrapper + 1;
            let relative_end = relative_start + expression_text.len();
            self.mappings.push(SourceMapping {
                generated: SourceSpan {
                    start: generated_start + relative_start,
                    end: generated_start + relative_end,
                },
                original: expression,
            });
            search_start = relative_end + 1;
        }
    }
}

fn preprocess_with_registry(
    source: &str,
    registry: &CommandRegistry<'_>,
) -> Result<PreprocessedSource, PreprocessError> {
    let tokens = lex(source)?;
    let mut ranges = Vec::new();
    let mut range_start = 0usize;
    let mut parens = 0usize;
    let mut brackets = 0usize;
    let mut brace_stack = Vec::new();
    let mut map_depth = 0usize;

    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Open('(') => parens += 1,
            TokenKind::Close(')') => parens = parens.saturating_sub(1),
            TokenKind::Open('[') => brackets += 1,
            TokenKind::Close(']') => brackets = brackets.saturating_sub(1),
            TokenKind::MapOpen => {
                brace_stack.push(true);
                map_depth += 1;
            }
            TokenKind::Open('{') => {
                if parens == 0 && brackets == 0 && map_depth == 0 {
                    ranges.push((range_start, token.end));
                    range_start = token.end;
                }
                brace_stack.push(false);
            }
            TokenKind::Close('}') => {
                let closes_map = brace_stack.pop().unwrap_or(false);
                if closes_map {
                    map_depth = map_depth.saturating_sub(1);
                } else if parens == 0 && brackets == 0 && map_depth == 0 {
                    ranges.push((range_start, token.start));
                    range_start = token.end;
                }
            }
            TokenKind::Semicolon if parens == 0 && brackets == 0 && map_depth == 0 => {
                ranges.push((range_start, token.start));
                range_start = token.end;
            }
            TokenKind::Newline if parens == 0 && brackets == 0 && map_depth == 0 => {
                let next = significant_after(&tokens, index);
                if next != Some(TokenKind::Pipe)
                    && !incomplete_expression_before(&tokens, index, range_start, source, registry)
                {
                    ranges.push((range_start, token.start));
                    range_start = token.end;
                }
            }
            _ => {}
        }
    }
    ranges.push((range_start, source.len()));

    let mut output = Output {
        source: String::with_capacity(source.len()),
        mappings: Vec::new(),
    };
    let mut cursor = 0usize;
    for (start, end) in ranges {
        if start > cursor {
            output.append(
                &source[cursor..start],
                SourceSpan {
                    start: cursor,
                    end: start,
                },
            );
        }
        if end > start {
            if let Some(rewritten) = transform_statement(source, &tokens, start, end, registry)? {
                output.append_rewrite(source, rewritten, SourceSpan { start, end });
            } else {
                output.append(&source[start..end], SourceSpan { start, end });
            }
        }
        cursor = end;
    }
    if cursor < source.len() {
        output.append(
            &source[cursor..],
            SourceSpan {
                start: cursor,
                end: source.len(),
            },
        );
    }
    Ok(PreprocessedSource {
        source: output.source,
        mappings: output.mappings,
    })
}

fn incomplete_expression_before(
    tokens: &[Token],
    index: usize,
    range_start: usize,
    source: &str,
    registry: &CommandRegistry<'_>,
) -> bool {
    let Some(previous) = tokens[..index]
        .iter()
        .rev()
        .find(|token| !trivia(token.kind))
    else {
        return false;
    };

    if previous.kind == TokenKind::Pipe {
        return true;
    }
    if starts_shell_statement(tokens, index, range_start, source, registry) {
        return false;
    }
    if previous.kind == TokenKind::Ident {
        return matches!(
            &source[previous.start..previous.end],
            "and" | "or" | "in" | "is" | "not"
        );
    }
    if !matches!(previous.kind, TokenKind::Other) {
        return false;
    }

    let prefix = source[..previous.end].trim_end();
    [
        "..=", "===", "!==", "<<=", ">>=", "**=", "+=", "-=", "*=", "/=", "%=", "==", "!=", "<=",
        ">=", "&&", "||", "<<", ">>", "**", "..", "=>", "??", "=", ",", "+", "-", "*", "/", "%",
        "<", ">", "&", "|", "^", "!", "?", "~",
    ]
    .iter()
    .any(|operator| prefix.ends_with(operator))
}

fn starts_shell_statement(
    tokens: &[Token],
    end: usize,
    range_start: usize,
    source: &str,
    registry: &CommandRegistry<'_>,
) -> bool {
    let Some((first_index, first)) = tokens[..end]
        .iter()
        .enumerate()
        .find(|(_, token)| token.start >= range_start && !trivia(token.kind))
    else {
        return false;
    };
    if first.kind == TokenKind::At {
        return true;
    }
    if first.kind != TokenKind::Ident
        || ordinary_rhai_follows(source, &tokens[first_index + 1..end])
    {
        return false;
    }
    let name = &source[first.start..first.end];
    registry.resolve(name).is_some_and(|spec| {
        matches!(
            spec.syntax,
            CommandSyntax::NoArguments | CommandSyntax::ShellArguments
        )
    })
}

fn significant_after(tokens: &[Token], index: usize) -> Option<TokenKind> {
    tokens[index + 1..]
        .iter()
        .find(|token| !trivia(token.kind))
        .map(|token| token.kind)
}

fn transform_statement(
    source: &str,
    all_tokens: &[Token],
    start: usize,
    end: usize,
    registry: &CommandRegistry<'_>,
) -> Result<Option<Rewrite>, PreprocessError> {
    let tokens: Vec<Token> = all_tokens
        .iter()
        .copied()
        .filter(|t| t.start >= start && t.end <= end)
        .collect();
    let Some(first_index) = tokens.iter().position(|token| !trivia(token.kind)) else {
        return Ok(None);
    };
    let last_index = tokens
        .iter()
        .rposition(|token| !trivia(token.kind))
        .unwrap();
    let leading = &source[start..tokens[first_index].start];
    let trailing = &source[tokens[last_index].end..end];

    let pipes = top_level_pipes(&tokens, first_index, last_index);
    let executable = tokens[first_index].kind == TokenKind::At;
    let transformed = if executable && !pipes.is_empty() {
        return Err(error(
            source,
            tokens[pipes[0]].start,
            PreprocessErrorKind::ExecutablePipelineUnsupported,
            "executable launches cannot be used as pipeline inputs".into(),
        ));
    } else if executable {
        transform_executable(source, &tokens[first_index..=last_index])?
    } else if pipes.is_empty() {
        transform_command(source, &tokens[first_index..=last_index], registry)?
    } else {
        transform_pipeline(source, &tokens[first_index..=last_index], registry)?
    };
    Ok(transformed.map(|mut body| {
        shift_mappings(&mut body.mappings, leading.len());
        body.source = format!("{leading}{}{trailing}", body.source);
        preserve_newline_count(&source[start..end], &mut body.source);
        body
    }))
}

fn shift_mappings(mappings: &mut [SourceMapping], offset: usize) {
    for mapping in mappings {
        mapping.generated.start += offset;
        mapping.generated.end += offset;
    }
}

fn preserve_newline_count(original: &str, generated: &mut String) {
    let original_count = original.bytes().filter(|byte| *byte == b'\n').count();
    let generated_count = generated.bytes().filter(|byte| *byte == b'\n').count();
    if generated_count > original_count {
        let mut excess = generated_count - original_count;
        while excess != 0 {
            let newline = generated.rfind('\n').unwrap();
            generated.replace_range(newline..newline + 1, " ");
            excess -= 1;
        }
    } else {
        for _ in generated_count..original_count {
            generated.push('\n');
        }
    }
}

fn top_level_pipes(tokens: &[Token], first: usize, last: usize) -> Vec<usize> {
    let mut result = Vec::new();
    let (mut parens, mut brackets, mut braces) = (0usize, 0usize, 0usize);
    for (index, token) in tokens.iter().enumerate().take(last + 1).skip(first) {
        match token.kind {
            TokenKind::Open('(') => parens += 1,
            TokenKind::Close(')') => parens = parens.saturating_sub(1),
            TokenKind::Open('[') => brackets += 1,
            TokenKind::Close(']') => brackets = brackets.saturating_sub(1),
            TokenKind::Open('{') | TokenKind::MapOpen => braces += 1,
            TokenKind::Close('}') => braces = braces.saturating_sub(1),
            TokenKind::Pipe if parens == 0 && brackets == 0 && braces == 0 => result.push(index),
            _ => {}
        }
    }
    result
}

fn transform_executable(
    source: &str,
    tokens: &[Token],
) -> Result<Option<Rewrite>, PreprocessError> {
    let at = tokens.iter().find(|token| !trivia(token.kind)).unwrap();
    let code_end = command_code_end(tokens, source.len());
    let raw = &source[at.end..code_end];
    let remainder = raw.trim_start();
    if remainder.is_empty() {
        return Err(error(
            source,
            at.end,
            PreprocessErrorKind::MissingExecutableTarget,
            "executable sigil `@` requires a target".into(),
        ));
    }

    let target_start = at.end + (raw.len() - remainder.len());
    let target_end = remainder
        .find(char::is_whitespace)
        .unwrap_or(remainder.len());
    let target = &remainder[..target_end];
    if target.is_empty() || !target.bytes().all(valid_executable_target_byte) {
        return Err(error(
            source,
            target_start,
            PreprocessErrorKind::InvalidExecutableTarget,
            format!("invalid executable target `{target}`"),
        ));
    }

    let raw_args = &remainder[target_end..];
    let args = raw_args.trim();
    let args_offset = target_start + target_end + raw_args.find(args).unwrap_or(0);
    let words = shell_words(source, args, args_offset)?;
    let mut generated = String::from("__ginkgo_execute(\"");
    generated.push_str(&escape_rhai(target));
    generated.push_str("\", [");
    append_arguments(&mut generated, &words.words);
    generated.push_str("])");
    generated.push_str(&source[code_end..tokens.last().unwrap().end]);
    Ok(Some(Rewrite {
        source: generated,
        interpolations: words.interpolations,
        mappings: Vec::new(),
    }))
}

fn valid_executable_target_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
}

fn transform_command(
    source: &str,
    tokens: &[Token],
    registry: &CommandRegistry<'_>,
) -> Result<Option<Rewrite>, PreprocessError> {
    let first = tokens.iter().position(|token| !trivia(token.kind)).unwrap();
    if tokens[first].kind != TokenKind::Ident {
        return Ok(None);
    }
    let name = &source[tokens[first].start..tokens[first].end];
    let Some(spec) = registry.resolve(name) else {
        return Ok(None);
    };
    if ordinary_rhai_follows(source, &tokens[first + 1..]) {
        return Ok(None);
    }
    let args_start = tokens[first].end;
    let args_end = command_code_end(tokens, source.len());
    let raw_args = &source[args_start..args_end];
    let args_source = raw_args.trim();
    let args_offset = args_start + raw_args.find(args_source).unwrap_or(0);
    let comment = &source[args_end..tokens.last().unwrap().end];
    let mut call = command_call(source, spec, args_source, args_offset)?;
    call.source.push_str(comment);
    Ok(Some(call))
}

fn ordinary_rhai_follows(source: &str, tokens: &[Token]) -> bool {
    let Some((next_index, next)) = tokens
        .iter()
        .enumerate()
        .find(|(_, token)| !trivia(token.kind))
    else {
        return false;
    };
    let remainder = &source[next.start..];
    if ["(", ".", "[", "::"]
        .iter()
        .any(|operator| remainder.starts_with(operator))
    {
        return true;
    }
    if next.kind == TokenKind::Ident
        && matches!(
            &source[next.start..next.end],
            "and" | "or" | "in" | "is" | "not"
        )
    {
        return true;
    }
    if remainder.starts_with("|>") {
        return false;
    }

    const OPERATORS: &[&str] = &[
        "===", "!==", "**=", "<<=", ">>=", "..=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        "?.", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "**", "??", "..", "=", "+", "-", "*",
        "/", "%", "<", ">", "&", "|", "^", "!", "?", "~",
    ];
    let Some(operator) = OPERATORS
        .iter()
        .find(|operator| remainder.starts_with(**operator))
    else {
        return false;
    };

    let separated = tokens[..next_index].iter().any(|token| trivia(token.kind));
    if !separated || operator.len() > 1 || *operator == "=" {
        return true;
    }

    source[next.start + operator.len()..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
}

fn command_code_end(tokens: &[Token], fallback: usize) -> usize {
    let mut nesting = 0usize;
    for token in tokens {
        match token.kind {
            TokenKind::Open(_) | TokenKind::MapOpen => nesting += 1,
            TokenKind::Close(_) => nesting = nesting.saturating_sub(1),
            TokenKind::Comment if nesting == 0 => return token.start,
            _ => {}
        }
    }
    tokens.last().map_or(fallback, |token| token.end)
}

fn command_call(
    source: &str,
    spec: &CommandSpec<'_>,
    args_source: &str,
    args_offset: usize,
) -> Result<Rewrite, PreprocessError> {
    match spec.syntax {
        CommandSyntax::NoArguments => {
            if !args_source.is_empty() {
                return Err(error(
                    source,
                    args_offset,
                    PreprocessErrorKind::UnexpectedArguments,
                    format!(
                        "command `{}` does not accept arguments",
                        spec.canonical_name
                    ),
                ));
            }
            Ok(format!(
                "__ginkgo_command(\"{}\", [])",
                escape_rhai(spec.canonical_name)
            )
            .into())
        }
        CommandSyntax::ShellArguments => {
            let words = shell_words(source, args_source, args_offset)?;
            check_count(source, spec, words.words.len(), args_offset)?;
            let mut call = String::from("__ginkgo_command(\"");
            call.push_str(&escape_rhai(spec.canonical_name));
            call.push_str("\", [");
            append_arguments(&mut call, &words.words);
            call.push_str("])");
            Ok(Rewrite {
                source: call,
                interpolations: words.interpolations,
                mappings: Vec::new(),
            })
        }
        CommandSyntax::RhaiExpression => {
            let count = usize::from(!args_source.trim().is_empty());
            check_count(source, spec, count, args_offset)?;
            Ok(format!("{}({})", spec.canonical_name, args_source.trim()).into())
        }
    }
}

fn check_count(
    source: &str,
    spec: &CommandSpec<'_>,
    count: usize,
    offset: usize,
) -> Result<(), PreprocessError> {
    if count < spec.min_args {
        return Err(error(
            source,
            offset,
            PreprocessErrorKind::TooFewArguments,
            format!(
                "command `{}` expects at least {} argument(s), but got {count}",
                spec.canonical_name, spec.min_args
            ),
        ));
    }
    if let Some(maximum) = spec.max_args {
        if count > maximum {
            return Err(error(
                source,
                offset,
                PreprocessErrorKind::TooManyArguments,
                format!(
                    "command `{}` accepts at most {maximum} argument(s), but got {count}",
                    spec.canonical_name
                ),
            ));
        }
    }
    Ok(())
}

fn append_arguments(output: &mut String, arguments: &[String]) {
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(argument);
    }
}

fn transform_pipeline(
    source: &str,
    tokens: &[Token],
    registry: &CommandRegistry<'_>,
) -> Result<Option<Rewrite>, PreprocessError> {
    let pipes = top_level_pipes(tokens, 0, tokens.len() - 1);
    if pipes.is_empty() {
        return Ok(None);
    }
    let mut bounds = Vec::new();
    let mut token_start = 0usize;
    for pipe in &pipes {
        bounds.push((token_start, *pipe));
        token_start = *pipe + 1;
    }
    bounds.push((token_start, tokens.len()));

    let (base_start, base_end) = token_slice_span(tokens, bounds[0]);
    let base_text = source[base_start..base_end].trim();
    if base_text.is_empty() {
        return Err(error(
            source,
            tokens[pipes[0]].start,
            PreprocessErrorKind::InvalidPipelineStage,
            "pipeline is missing its input expression".into(),
        ));
    }
    let base_tokens = &tokens[bounds[0].0..bounds[0].1];
    let mut value =
        transform_command(source, base_tokens, registry)?.unwrap_or_else(|| base_text.into());
    value.mappings.push(SourceMapping {
        generated: SourceSpan {
            start: 0,
            end: value.source.len(),
        },
        original: SourceSpan {
            start: base_start,
            end: base_end,
        },
    });

    for &(from, to) in &bounds[1..] {
        let (stage_start, stage_end) = token_slice_span(tokens, (from, to));
        let stage = source[stage_start..stage_end].trim();
        if stage.is_empty() {
            return Err(error(
                source,
                stage_start,
                PreprocessErrorKind::InvalidPipelineStage,
                "pipeline is missing a stage after `|>`".into(),
            ));
        }
        value = transform_stage(
            source,
            &tokens[from..to],
            stage,
            stage_start,
            registry,
            value,
        )?;
    }
    Ok(Some(value))
}

fn token_slice_span(tokens: &[Token], bounds: (usize, usize)) -> (usize, usize) {
    let slice = &tokens[bounds.0..bounds.1];
    let first = slice
        .iter()
        .find(|token| !trivia(token.kind))
        .unwrap_or(&slice[0]);
    let last = slice
        .iter()
        .rev()
        .find(|token| !trivia(token.kind))
        .unwrap_or(slice.last().unwrap());
    (first.start, last.end)
}

fn transform_stage(
    source: &str,
    tokens: &[Token],
    stage: &str,
    stage_offset: usize,
    registry: &CommandRegistry<'_>,
    input: Rewrite,
) -> Result<Rewrite, PreprocessError> {
    let first = tokens.iter().find(|token| !trivia(token.kind)).unwrap();
    if first.kind != TokenKind::Ident {
        return Err(error(
            source,
            stage_offset,
            PreprocessErrorKind::InvalidPipelineStage,
            "pipeline stage must be a function or registered shell command".into(),
        ));
    }
    let name = &source[first.start..first.end];
    let first_index = tokens
        .iter()
        .position(|token| token.start == first.start)
        .unwrap();
    if !ordinary_rhai_follows(source, &tokens[first_index + 1..]) {
        if let Some(spec) = registry.resolve(name) {
            if spec.syntax == CommandSyntax::ShellArguments {
                let raw_args = &source[first.end..tokens.last().unwrap().end];
                let args = raw_args.trim();
                let args_offset = first.end + raw_args.find(args).unwrap_or(0);
                let words = shell_words(source, args, args_offset)?;
                check_count(source, spec, 1 + words.words.len(), args_offset)?;
                let escaped_name = escape_rhai(spec.canonical_name);
                let prefix = format!("__ginkgo_pipe_command(\"{escaped_name}\", ");
                let mut mappings = input.mappings;
                shift_mappings(&mut mappings, prefix.len());
                mappings.push(SourceMapping {
                    generated: SourceSpan {
                        start: "__ginkgo_pipe_command(\"".len(),
                        end: "__ginkgo_pipe_command(\"".len() + escaped_name.len(),
                    },
                    original: SourceSpan {
                        start: first.start,
                        end: first.end,
                    },
                });
                let mut result = prefix;
                result.push_str(&input.source);
                result.push_str(", [");
                append_arguments(&mut result, &words.words);
                result.push_str("])");
                let mut interpolations = input.interpolations;
                interpolations.extend(words.interpolations);
                return Ok(Rewrite {
                    source: result,
                    interpolations,
                    mappings,
                });
            }
            if spec.syntax == CommandSyntax::RhaiExpression {
                let raw_args = &source[first.end..tokens.last().unwrap().end];
                let args = raw_args.trim();
                let count = 1 + usize::from(!args.is_empty());
                check_count(source, spec, count, first.end)?;
                let prefix = format!("{}(", spec.canonical_name);
                let mut mappings = input.mappings;
                shift_mappings(&mut mappings, prefix.len());
                mappings.push(SourceMapping {
                    generated: SourceSpan {
                        start: 0,
                        end: spec.canonical_name.len(),
                    },
                    original: SourceSpan {
                        start: first.start,
                        end: first.end,
                    },
                });
                let mut result = prefix;
                result.push_str(&input.source);
                if !args.is_empty() {
                    result.push_str(", ");
                    let generated_start = result.len();
                    result.push_str(args);
                    let original_start = first.end + raw_args.find(args).unwrap();
                    mappings.push(SourceMapping {
                        generated: SourceSpan {
                            start: generated_start,
                            end: generated_start + args.len(),
                        },
                        original: SourceSpan {
                            start: original_start,
                            end: original_start + args.len(),
                        },
                    });
                }
                result.push(')');
                return Ok(Rewrite {
                    source: result,
                    interpolations: input.interpolations,
                    mappings,
                });
            }
            if spec.syntax == CommandSyntax::NoArguments {
                return Err(error(
                    source,
                    first.start,
                    PreprocessErrorKind::UnexpectedArguments,
                    format!(
                        "command `{}` does not accept piped input",
                        spec.canonical_name
                    ),
                ));
            }
        }
    }

    let rest = stage[name.len()..].trim();
    if rest.is_empty() || (rest.starts_with('(') && rest.ends_with(')')) {
        let prefix = format!("{name}(");
        let mut mappings = input.mappings;
        shift_mappings(&mut mappings, prefix.len());
        mappings.push(SourceMapping {
            generated: SourceSpan {
                start: 0,
                end: name.len(),
            },
            original: SourceSpan {
                start: first.start,
                end: first.end,
            },
        });
        let mut generated = prefix;
        generated.push_str(&input.source);
        if !rest.is_empty() {
            let inside = rest[1..rest.len() - 1].trim();
            if !inside.is_empty() {
                generated.push_str(", ");
                let generated_start = generated.len();
                generated.push_str(inside);
                let raw_inside = &source[first.end..tokens.last().unwrap().end];
                let original_start = first.end + raw_inside.find(inside).unwrap();
                mappings.push(SourceMapping {
                    generated: SourceSpan {
                        start: generated_start,
                        end: generated_start + inside.len(),
                    },
                    original: SourceSpan {
                        start: original_start,
                        end: original_start + inside.len(),
                    },
                });
            }
        }
        generated.push(')');
        return Ok(Rewrite {
            source: generated,
            interpolations: input.interpolations,
            mappings,
        });
    }
    Err(error(
        source,
        stage_offset,
        PreprocessErrorKind::InvalidPipelineStage,
        format!("invalid pipeline stage `{stage}`"),
    ))
}

fn shell_words(
    source: &str,
    input: &str,
    base_offset: usize,
) -> Result<ShellWords, PreprocessError> {
    let bytes = input.as_bytes();
    let mut words = Vec::new();
    let mut interpolations = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let word_start = index;
        let mut fragments: Vec<(bool, String)> = Vec::new();
        let mut literal = String::new();
        let mut quote = None;
        while index < bytes.len() {
            let byte = bytes[index];
            if quote.is_none() && byte.is_ascii_whitespace() {
                break;
            }
            if byte == b'\\' {
                let escape_offset = index;
                index += 1;
                if index == bytes.len() {
                    return Err(error(
                        source,
                        base_offset + escape_offset,
                        PreprocessErrorKind::InvalidEscape,
                        "trailing backslash in shell argument".into(),
                    ));
                }
                let escaped = input[index..].chars().next().unwrap();
                if quote.is_none()
                    && !(escaped.is_whitespace()
                        || matches!(escaped, '\'' | '"' | '`' | '\\' | '$' | '|'))
                {
                    return Err(error(
                        source,
                        base_offset + escape_offset,
                        PreprocessErrorKind::InvalidEscape,
                        format!("invalid unquoted shell escape `\\{escaped}`"),
                    ));
                }
                literal.push(escaped);
                index += escaped.len_utf8();
                continue;
            }
            if byte == b'$' && bytes.get(index + 1) == Some(&b'(') && quote != Some(b'\'') {
                if !literal.is_empty() {
                    fragments.push((false, core::mem::take(&mut literal)));
                }
                let expression_start = index + 2;
                let (expression_end, next_index) =
                    interpolation_end(source, input, expression_start, base_offset, word_start)?;
                index = next_index;
                let raw_expression = &input[expression_start..expression_end];
                let expression = raw_expression.trim();
                let expression_offset =
                    expression_start + raw_expression.find(expression).unwrap_or(0);
                interpolations.push(SourceSpan {
                    start: base_offset + expression_offset,
                    end: base_offset + expression_offset + expression.len(),
                });
                fragments.push((true, expression.into()));
                continue;
            }
            if let Some(q) = quote {
                if byte == q {
                    quote = None;
                    index += 1;
                    continue;
                }
                let ch = input[index..].chars().next().unwrap();
                literal.push(ch);
                index += ch.len_utf8();
                continue;
            }
            if matches!(byte, b'\'' | b'"' | b'`') {
                quote = Some(byte);
                index += 1;
                continue;
            }
            let ch = input[index..].chars().next().unwrap();
            literal.push(ch);
            index += ch.len_utf8();
        }
        if !literal.is_empty() || fragments.is_empty() {
            fragments.push((false, literal));
        }
        let stringify_expressions = fragments.len() > 1;
        let mut rendered = String::new();
        for (fragment_index, (expression, text)) in fragments.into_iter().enumerate() {
            if fragment_index != 0 {
                rendered.push_str(" + ");
            }
            if expression && stringify_expressions {
                rendered.push_str("__ginkgo_shell_string(");
                rendered.push_str(&text);
                rendered.push(')');
            } else if expression {
                rendered.push('(');
                rendered.push_str(&text);
                rendered.push(')');
            } else {
                rendered.push('"');
                rendered.push_str(&escape_rhai(&text));
                rendered.push('"');
            }
        }
        words.push(rendered);
    }
    Ok(ShellWords {
        words,
        interpolations,
    })
}

fn interpolation_end(
    source: &str,
    input: &str,
    expression_start: usize,
    base_offset: usize,
    word_start: usize,
) -> Result<(usize, usize), PreprocessError> {
    let tail = &input[expression_start..];
    for (candidate, _) in tail.match_indices(')') {
        let prefix_end = candidate + 1;
        let Ok(tokens) = lex(&tail[..prefix_end]) else {
            continue;
        };
        let mut depth = 1usize;
        for token in tokens {
            match token.kind {
                TokenKind::Open('(') => depth += 1,
                TokenKind::Close(')') => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if depth == 0 {
            return Ok((expression_start + candidate, expression_start + prefix_end));
        }
    }
    Err(error(
        source,
        base_offset + word_start,
        PreprocessErrorKind::UnterminatedInterpolation,
        "unterminated `$(...)` interpolation".into(),
    ))
}

fn escape_rhai(value: &str) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            _ => output.push(ch),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    static SPECS: &[CommandSpec<'static>] = &[
        CommandSpec::no_arguments("clear", &["cls"]),
        CommandSpec::shell("echo", &["say"], 1, None),
        CommandSpec::shell("grep", &[], 1, Some(2)),
        CommandSpec::shell("cat", &[], 1, None),
        CommandSpec::shell("copy-to", &[], 2, Some(2)),
        CommandSpec::shell("ls", &[], 1, Some(1)),
        CommandSpec::shell("rm", &[], 1, None),
        CommandSpec::shell("filter", &[], 1, Some(1)),
        CommandSpec::expression("open", &["launch"], 1, Some(2)),
        CommandSpec::expression("print", &[], 1, Some(1)),
    ];

    fn preprocess(source: &str) -> Result<PreprocessedSource, PreprocessError> {
        CommandRegistry::new(SPECS).unwrap().preprocess(source)
    }

    #[test]
    fn executable_sigil_rewrites_targets_and_shell_arguments() {
        let source = "@edit\n@/system/tool.elf --flag $(value)\n@disk:/tools/run-file arg";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source,
            "__ginkgo_execute(\"edit\", [])\n__ginkgo_execute(\"/system/tool.elf\", [\"--flag\", (value)])\n__ginkgo_execute(\"disk:/tools/run-file\", [\"arg\"])"
        );
        assert_eq!(
            result.source.bytes().filter(|byte| *byte == b'\n').count(),
            source.bytes().filter(|byte| *byte == b'\n').count()
        );
    }

    #[test]
    fn executable_sigil_is_boundary_only_and_preserves_delimiters() {
        let source =
            "let launch = @edit; [@edit]; call(@edit); \"@edit\"; // @edit\nif true { @edit; }\n";
        assert_eq!(
            preprocess(source).unwrap().source,
            "let launch = @edit; [@edit]; call(@edit); \"@edit\"; // @edit\nif true { __ginkgo_execute(\"edit\", []); }\n"
        );
    }

    #[test]
    fn executable_sigil_validates_target_and_rejects_pipelines() {
        let missing = preprocess("@").unwrap_err();
        assert_eq!(missing.kind, PreprocessErrorKind::MissingExecutableTarget);
        assert_eq!((missing.offset, missing.line, missing.column), (1, 1, 2));

        for source in ["@bad?target", "@\"quoted\"", "@$(target)"] {
            let invalid = preprocess(source).unwrap_err();
            assert_eq!(invalid.kind, PreprocessErrorKind::InvalidExecutableTarget);
            assert_eq!((invalid.offset, invalid.line, invalid.column), (1, 1, 2));
        }

        let pipeline = preprocess("@edit |> use").unwrap_err();
        assert_eq!(
            pipeline.kind,
            PreprocessErrorKind::ExecutablePipelineUnsupported
        );
        assert_eq!((pipeline.offset, pipeline.line, pipeline.column), (6, 1, 7));
        assert!(pipeline
            .message
            .contains("cannot be used as pipeline inputs"));
    }

    #[test]
    fn executable_interpolations_have_direct_mappings() {
        let source = "@tool --first $(one + 1) $(two)";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source,
            "__ginkgo_execute(\"tool\", [\"--first\", (one + 1), (two)])"
        );
        for expression in ["one + 1", "two"] {
            let generated = result.source.find(expression).unwrap();
            let original = source.find(expression).unwrap();
            assert_eq!(
                result.original_span(generated),
                Some(SourceSpan {
                    start: original,
                    end: original + expression.len(),
                })
            );
        }
    }

    #[test]
    fn executable_arguments_share_shell_escape_validation() {
        assert_eq!(
            preprocess(r#"@edit one\ two left\|right"#).unwrap().source,
            r#"__ginkgo_execute("edit", ["one two", "left|right"])"#
        );
        let invalid = preprocess("@edit bad\\q").unwrap_err();
        assert_eq!(invalid.kind, PreprocessErrorKind::InvalidEscape);
        assert_eq!((invalid.offset, invalid.line, invalid.column), (9, 1, 10));
    }

    #[test]
    fn complete_command_examples() {
        let source = "clear\necho hello 'two words'\nopen path, true\nprint 40 + 2\nsay alias\n";
        assert_eq!(preprocess(source).unwrap().source,
            "__ginkgo_command(\"clear\", [])\n__ginkgo_command(\"echo\", [\"hello\", \"two words\"])\nopen(path, true)\nprint(40 + 2)\n__ginkgo_command(\"echo\", [\"alias\"])\n");
    }

    #[test]
    fn registry_resolves_aliases_and_rejects_every_collision() {
        let registry = CommandRegistry::new(SPECS).unwrap();
        assert_eq!(registry.resolve("say").unwrap().canonical_name, "echo");
        assert!(matches!(
            CommandRegistry::new(&[
                CommandSpec::no_arguments("a", &[]),
                CommandSpec::no_arguments("a", &[])
            ]),
            Err(RegistryError::DuplicateCanonicalName { .. })
        ));
        assert!(matches!(
            CommandRegistry::new(&[
                CommandSpec::no_arguments("a", &["x"]),
                CommandSpec::no_arguments("b", &["x"])
            ]),
            Err(RegistryError::DuplicateAlias { .. })
        ));
        assert!(matches!(
            CommandRegistry::new(&[
                CommandSpec::no_arguments("a", &["b"]),
                CommandSpec::no_arguments("b", &[])
            ]),
            Err(RegistryError::NameAliasCollision { .. })
        ));
    }

    #[test]
    fn ordinary_rhai_and_non_boundaries_are_suppressed() {
        let source = "let echo = 4; echo(1); object.echo\nif true {\n  echo nested\n}\n";
        assert_eq!(preprocess(source).unwrap().source,
            "let echo = 4; echo(1); object.echo\nif true {\n  __ginkgo_command(\"echo\", [\"nested\"])\n}\n");
    }

    #[test]
    fn ordinary_rhai_operators_after_registered_names_are_suppressed() {
        let source = "echo (value)\necho .value\necho [index]\necho = value\necho == value\necho != value\necho += value\necho -= value\necho *= value\necho /= value\necho :: value\necho /* trivia */ == value\n";
        assert_eq!(preprocess(source).unwrap().source, source);
    }

    #[test]
    fn map_literal_braces_never_create_command_boundaries() {
        let source = "let commands = #{\n  ls: rm,\n  nested: #{ echo: ls, clear: print },\n  value: if ready { ls } else { rm }\n};\nls /system\n";
        assert_eq!(
            preprocess(source).unwrap().source,
            "let commands = #{\n  ls: rm,\n  nested: #{ echo: ls, clear: print },\n  value: if ready { ls } else { rm }\n};\n__ginkgo_command(\"ls\", [\"/system\"])\n"
        );
    }

    #[test]
    fn incomplete_expression_newlines_do_not_create_command_boundaries() {
        for source in [
            "let x = 1 +\n ls;",
            "let x = value =\n ls;",
            "let x = first,\n ls;",
            "let x = left and\n ls;",
            "let x = left ||\n ls;",
            "let x = left ==\n ls;",
            "let x = left <\n ls;",
            "let x = 0..\n ls;",
            "let x = total /\n ls;",
            "let x = total -\n ls;",
            "let x = flags |\n ls;",
            "let x = 1 + /* continue */\n ls;",
        ] {
            assert_eq!(preprocess(source).unwrap().source, source, "{source}");
        }

        assert_eq!(
            preprocess("ls /system\nrm --flag\necho word\nls /system\n")
                .unwrap()
                .source,
            "__ginkgo_command(\"ls\", [\"/system\"])\n__ginkgo_command(\"rm\", [\"--flag\"])\n__ginkgo_command(\"echo\", [\"word\"])\n__ginkgo_command(\"ls\", [\"/system\"])\n"
        );
        assert_eq!(
            preprocess("print value and\n ls;").unwrap().source,
            "print(value and\n ls);"
        );
    }

    #[test]
    fn nested_comments_do_not_truncate_shell_command_source() {
        let source = "ls $(path /* choose ) carefully */ + suffix) // trailing";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source,
            "__ginkgo_command(\"ls\", [(path /* choose ) carefully */ + suffix)]) // trailing"
        );
        let expression = "path /* choose ) carefully */ + suffix";
        let generated = result.source.find(expression).unwrap();
        let original = source.find(expression).unwrap();
        assert_eq!(
            result.original_span(generated),
            Some(SourceSpan {
                start: original,
                end: original + expression.len(),
            })
        );

        let nested = "ls $(pick(call(/* call */ value), [one /* array */], #{ key: two /* map */ })) // done";
        assert_eq!(
            preprocess(nested).unwrap().source,
            "__ginkgo_command(\"ls\", [(pick(call(/* call */ value), [one /* array */], #{ key: two /* map */ }))]) // done"
        );
    }

    #[test]
    fn same_line_rhai_operators_suppress_registered_commands_without_hiding_shell_args() {
        let ordinary = "ls / 2; ls - 1; ls + 1; ls * 2; ls % 2; ls ** 2; rm < limit; rm <= limit; rm > limit; rm >= limit; echo && enabled; echo || enabled; echo & mask; echo | mask; echo ^ mask; echo << bits; echo >> bits; ls .. end; ls ..= end; echo and enabled; echo or enabled; echo in values; echo is type; echo not enabled;";
        assert_eq!(preprocess(ordinary).unwrap().source, ordinary);

        let compact =
            "ls/2; ls+1; ls-1; ls*2; rm<limit; echo&&enabled; echo|mask; ls..end; clear+1;";
        assert_eq!(preprocess(compact).unwrap().source, compact);

        let compound = "ls %= 2; ls <<= 1; ls >>= 1; echo &= mask; echo |= mask; echo ^= mask; ls **= 2; echo ?? fallback;";
        assert_eq!(preprocess(compound).unwrap().source, compound);

        assert_eq!(
            preprocess("ls /system; rm --flag; clear; ls /system |> sort;")
                .unwrap()
                .source,
            "__ginkgo_command(\"ls\", [\"/system\"]); __ginkgo_command(\"rm\", [\"--flag\"]); __ginkgo_command(\"clear\", []); sort(__ginkgo_command(\"ls\", [\"/system\"]));"
        );
    }

    #[test]
    fn shell_interpolation_quotes_and_escapes_are_token_aware() {
        let result = preprocess(
            r#"echo hello\ world "quoted value" $(name + f(2)) pre$(x)post \$(literal)"#,
        )
        .unwrap();
        assert_eq!(
            result.source,
            r#"__ginkgo_command("echo", ["hello world", "quoted value", (name + f(2)), "pre" + __ginkgo_shell_string(x) + "post", "$(literal)"])"#,
        );
        assert_eq!(
            preprocess("echo \"hé$(name)\" '$(literal)'")
                .unwrap()
                .source,
            r#"__ginkgo_command("echo", ["hé" + __ginkgo_shell_string(name), "$(literal)"])"#,
        );
    }

    #[test]
    fn mixed_interpolations_are_stringified_but_standalone_values_stay_dynamic() {
        let source = "echo pre$(42)post $(42)";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source,
            "__ginkgo_command(\"echo\", [\"pre\" + __ginkgo_shell_string(42) + \"post\", (42)])"
        );

        let original_positions: Vec<usize> =
            source.match_indices("42").map(|(index, _)| index).collect();
        let generated_positions: Vec<usize> = result
            .source
            .match_indices("42")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(original_positions.len(), 2);
        assert_eq!(generated_positions.len(), 2);
        for (generated, original) in generated_positions.into_iter().zip(original_positions) {
            assert_eq!(
                result.original_span(generated),
                Some(SourceSpan {
                    start: original,
                    end: original + 2,
                })
            );
        }
    }

    #[test]
    fn pipelines_are_left_associative_and_support_multiline_shell_stages() {
        let source = "items |> filter(|x| x > 2)\n  |> grep result\n  |> len\n";
        assert_eq!(
            preprocess(source).unwrap().source,
            "len(__ginkgo_pipe_command(\"grep\", filter(items, |x| x > 2), [\"result\"]))\n\n\n"
        );
    }

    #[test]
    fn piped_input_counts_as_a_shell_argument_but_stays_outside_the_array() {
        assert_eq!(
            preprocess("path |> cat").unwrap().source,
            "__ginkgo_pipe_command(\"cat\", path, [])"
        );
        assert_eq!(
            preprocess("files |> copy-to /backup").unwrap().source,
            "__ginkgo_pipe_command(\"copy-to\", files, [\"/backup\"])"
        );
        let error = preprocess("path |> clear").unwrap_err();
        assert_eq!(error.kind, PreprocessErrorKind::UnexpectedArguments);
        assert_eq!((error.offset, error.line, error.column), (8, 1, 9));
        assert_eq!(error.message, "command `clear` does not accept piped input");
    }

    #[test]
    fn multiline_pipeline_stages_and_base_have_narrow_mappings() {
        let source = "ls /system\n |> missing_function\n";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source.bytes().filter(|byte| *byte == b'\n').count(),
            source.bytes().filter(|byte| *byte == b'\n').count()
        );

        let generated_stage = result.source.find("missing_function").unwrap();
        let original_stage = source.find("missing_function").unwrap();
        let stage_span = result.original_span(generated_stage).unwrap();
        assert_eq!(
            stage_span,
            SourceSpan {
                start: original_stage,
                end: original_stage + "missing_function".len(),
            }
        );
        let prefix = &source[..stage_span.start];
        assert_eq!(prefix.bytes().filter(|byte| *byte == b'\n').count() + 1, 2);
        assert_eq!(prefix.rsplit_once('\n').unwrap().1.chars().count() + 1, 5);

        let generated_base = result.source.find("__ginkgo_command").unwrap();
        assert_eq!(
            result.original_span(generated_base),
            Some(SourceSpan { start: 0, end: 10 })
        );

        let call_source = "items |> filter(missing_value)";
        let call = preprocess(call_source).unwrap();
        let generated_argument = call.source.find("missing_value").unwrap();
        let original_argument = call_source.find("missing_value").unwrap();
        assert_eq!(
            call.original_span(generated_argument),
            Some(SourceSpan {
                start: original_argument,
                end: original_argument + "missing_value".len(),
            })
        );
    }

    #[test]
    fn four_line_pipeline_preserves_the_exact_newline_count() {
        let source = "items\n  |> filter(|x| x > 2)\n  |> grep result\n  |> len";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source.bytes().filter(|byte| *byte == b'\n').count(),
            source.bytes().filter(|byte| *byte == b'\n').count()
        );
        assert_eq!(
            result.source,
            "len(__ginkgo_pipe_command(\"grep\", filter(items, |x| x > 2), [\"result\"]))\n\n\n"
        );
    }

    #[test]
    fn complete_spec_pipeline_uses_exact_abi_and_expression_insertion() {
        assert_eq!(
            preprocess("ls /system |> filter(\".rhai\") |> sort |> print")
                .unwrap()
                .source,
            "print(sort(filter(__ginkgo_command(\"ls\", [\"/system\"]), \".rhai\")))"
        );
        assert_eq!(
            preprocess("items |> open options + 1").unwrap().source,
            "open(items, options + 1)"
        );
    }

    #[test]
    fn semicolons_and_braces_are_preserved_around_commands() {
        let source = "clear; { clear; }\nif true { clear; echo inside }\n";
        assert_eq!(
            preprocess(source).unwrap().source,
            "__ginkgo_command(\"clear\", []); { __ginkgo_command(\"clear\", []); }\nif true { __ginkgo_command(\"clear\", []); __ginkgo_command(\"echo\", [\"inside\"]) }\n"
        );
    }

    #[test]
    fn comments_strings_raw_strings_and_backticks_do_not_trigger() {
        let source = "// echo nope\n\"echo nope |> grep x\"\nr#\"clear /* hi */\"#\n`echo hi`\n/* outer /* echo */ clear */\n";
        assert_eq!(preprocess(source).unwrap().source, source);
    }

    #[test]
    fn interpolation_mappings_are_narrow_and_direct() {
        let source = "echo pre$(first + 1) $(second)";
        let result = preprocess(source).unwrap();
        assert_eq!(
            result.source,
            "__ginkgo_command(\"echo\", [\"pre\" + __ginkgo_shell_string(first + 1), (second)])"
        );

        for expression in ["first + 1", "second"] {
            let generated_start = result.source.find(expression).unwrap();
            let original_start = source.find(expression).unwrap();
            let expected = SourceSpan {
                start: original_start,
                end: original_start + expression.len(),
            };
            assert_eq!(result.original_span(generated_start), Some(expected));
            let mapping = result
                .mappings
                .iter()
                .find(|mapping| mapping.generated.start == generated_start)
                .unwrap();
            assert_eq!(
                &result.source[mapping.generated.start..mapping.generated.end],
                expression
            );
            assert_eq!(
                &source[mapping.original.start..mapping.original.end],
                expression
            );
        }
    }

    #[test]
    fn invalid_unquoted_shell_escape_reports_original_coordinates() {
        let invalid = preprocess("echo bad\\q").unwrap_err();
        assert_eq!(invalid.kind, PreprocessErrorKind::InvalidEscape);
        assert_eq!((invalid.offset, invalid.line, invalid.column), (8, 1, 9));
        assert!(invalid.message.contains("invalid unquoted shell escape"));

        assert_eq!(
            preprocess(r#"echo one\ two \"quoted\" back\\slash \$dollar left\|right"#)
                .unwrap()
                .source,
            r#"__ginkgo_command("echo", ["one two", "\"quoted\"", "back\\slash", "$dollar", "left|right"])"#
        );
    }

    #[test]
    fn argument_counts_and_diagnostics_use_original_coordinates() {
        let few = preprocess("\n  echo").unwrap_err();
        assert_eq!(few.kind, PreprocessErrorKind::TooFewArguments);
        assert_eq!((few.offset, few.line, few.column), (7, 2, 7));
        assert!(few.message.contains("at least 1"));

        let many = preprocess("grep a b c").unwrap_err();
        assert_eq!(many.kind, PreprocessErrorKind::TooManyArguments);
        assert_eq!((many.line, many.column), (1, 6));

        let unexpected = preprocess("clear now").unwrap_err();
        assert_eq!(unexpected.kind, PreprocessErrorKind::UnexpectedArguments);
        assert!(unexpected.to_string().contains("1:7"));
    }

    #[test]
    fn lexical_errors_report_the_original_location() {
        let error = preprocess("echo ok\n/* broken").unwrap_err();
        assert_eq!(error.kind, PreprocessErrorKind::UnterminatedBlockComment);
        assert_eq!((error.offset, error.line, error.column), (8, 2, 1));
        let error = preprocess("echo $(foo").unwrap_err();
        assert_eq!(error.kind, PreprocessErrorKind::UnterminatedInterpolation);
    }

    #[test]
    fn mappings_cover_rewritten_and_preserved_ranges() {
        let result = preprocess("echo hi\nlet x = 1").unwrap();
        assert_eq!(
            result.original_span(1),
            Some(SourceSpan { start: 0, end: 7 })
        );
        let let_offset = result.source.find("let").unwrap();
        assert_eq!(
            result.original_span(let_offset),
            Some(SourceSpan { start: 8, end: 17 })
        );
    }
}
