use std::{collections::BTreeMap, string::String, vec::Vec};

use ginkgo_shell_language::{CallMode, Host, Interpreter, List, Value};

#[derive(Default)]
struct TestHost {
    calls: Vec<(CallMode, String, List)>,
    includes: BTreeMap<String, String>,
    include_requests: Vec<String>,
    globs: BTreeMap<String, Vec<String>>,
}

impl Host for TestHost {
    fn call(&mut self, mode: CallMode, name: &str, args: List) -> Result<Value, String> {
        self.calls.push((mode, name.into(), args));
        Ok(Value::Unit)
    }

    fn include(&mut self, path: &str) -> Result<String, String> {
        self.include_requests.push(path.into());
        self.includes
            .get(path)
            .cloned()
            .ok_or_else(|| format!("missing include `{path}`"))
    }

    fn glob(&mut self, pattern: &str) -> Result<Vec<String>, String> {
        self.globs
            .get(pattern)
            .cloned()
            .ok_or_else(|| format!("unexpected glob `{pattern}`"))
    }
}

fn eval(source: &str, host: &mut TestHost) -> Value {
    Interpreter::new().eval(source, "test.gsh", host).unwrap()
}

#[test]
fn bare_commands_allow_empty_and_comma_separated_arguments() {
    let mut host = TestHost::default();
    eval("ping; command parameter1, parameter2", &mut host);
    assert_eq!(host.calls[0], (CallMode::Auto, "ping".into(), vec![]));
    assert_eq!(
        host.calls[1],
        (
            CallMode::Auto,
            "command".into(),
            vec![
                Value::String("parameter1".into()),
                Value::String("parameter2".into())
            ]
        )
    );
}

#[test]
fn quoted_commas_are_preserved() {
    let mut host = TestHost::default();
    eval("echo \"one,two\", \"three\"", &mut host);
    assert_eq!(
        host.calls[0].2,
        vec![
            Value::String("one,two".into()),
            Value::String("three".into())
        ]
    );
}

#[test]
fn globals_persist_between_eval_calls() {
    let mut interpreter = Interpreter::new();
    let mut host = TestHost::default();
    interpreter
        .eval("$answer = 42", "first", &mut host)
        .unwrap();
    assert_eq!(
        interpreter.eval("$answer", "second", &mut host).unwrap(),
        Value::Integer(42)
    );
}

#[test]
fn all_loop_forms_execute() {
    let source = r#"
for $x in @[1, 2, 3] do
    item $x
end
repeat 2 times
    repeated
end
$go = true
while $go do
    while_body
    $go = false
end
$ready = false
until $ready do
    until_body
    $ready = true
end
$again = true
do
    do_body
    $again = false
while $again
"#;
    let mut host = TestHost::default();
    eval(source, &mut host);
    let names: Vec<_> = host.calls.iter().map(|call| call.1.as_str()).collect();
    assert_eq!(
        names,
        [
            "item",
            "item",
            "item",
            "repeated",
            "repeated",
            "while_body",
            "until_body",
            "do_body"
        ]
    );
    assert_eq!(host.calls[2].2, vec![Value::Integer(3)]);
}

#[test]
fn functions_bind_arguments_and_return_values() {
    let source = r#"
def identity($value)
    return $value
end
identity 19
"#;
    let mut host = TestHost::default();
    assert_eq!(eval(source, &mut host), Value::Integer(19));
    assert!(host.calls.is_empty());
}

#[test]
fn aliases_take_precedence_and_preserve_explicit_modes() {
    let source = r#"
def short()
    return 99
end
alias short = target
short
alias app = !editor
app file.txt
alias builtin = %clear
builtin
alias rooted = /bin/tool
rooted
!short
%short
C:\bin\tool arg
./local.wasm arg
tools/nested.elf
"#;
    let mut host = TestHost::default();
    eval(source, &mut host);
    let modes_and_names: Vec<_> = host
        .calls
        .iter()
        .map(|call| (call.0, call.1.as_str()))
        .collect();
    assert_eq!(
        modes_and_names,
        [
            (CallMode::Auto, "target"),
            (CallMode::Application, "editor"),
            (CallMode::Builtin, "clear"),
            (CallMode::AbsolutePath, "/bin/tool"),
            (CallMode::Application, "short"),
            (CallMode::Builtin, "short"),
            (CallMode::AbsolutePath, "C:\\bin\\tool"),
            (CallMode::AbsolutePath, "./local.wasm"),
            (CallMode::AbsolutePath, "tools/nested.elf"),
        ]
    );
}

#[test]
fn alias_cycles_are_rejected_at_definition() {
    let mut interpreter = Interpreter::new();
    let mut host = TestHost::default();
    interpreter
        .eval("alias a = b", "aliases", &mut host)
        .unwrap();
    let error = interpreter
        .eval("alias b = a", "aliases", &mut host)
        .unwrap_err();
    assert!(error.to_string().contains("alias `b` creates a cycle"));
}

#[test]
fn includes_share_state_and_run_once() {
    let mut host = TestHost::default();
    host.includes.insert(
        "library.gsh".into(),
        "#pragma once\n$included = 7\ndef from_include()\n return $included\nend".into(),
    );
    let mut interpreter = Interpreter::new();
    interpreter
        .eval(
            "include \"library.gsh\"; include \"library.gsh\"",
            "main",
            &mut host,
        )
        .unwrap();
    assert_eq!(host.include_requests, ["library.gsh"]);
    assert_eq!(
        interpreter.eval("from_include", "main", &mut host).unwrap(),
        Value::Integer(7)
    );
}

#[test]
fn run_executes_every_time_and_shares_interpreter_state() {
    let mut host = TestHost::default();
    host.includes.insert(
        "task.gsh".into(),
        "$from_run = 23\ndef run_value()\n return $from_run\nend\nran_task".into(),
    );
    let mut interpreter = Interpreter::new();
    interpreter
        .eval("run \"task.gsh\"; run \"task.gsh\"", "main", &mut host)
        .unwrap();

    assert_eq!(host.include_requests, ["task.gsh", "task.gsh"]);
    assert_eq!(
        host.calls
            .iter()
            .map(|call| call.1.as_str())
            .collect::<Vec<_>>(),
        ["ran_task", "ran_task"]
    );
    assert_eq!(
        interpreter.eval("run_value", "main", &mut host).unwrap(),
        Value::Integer(23)
    );
}

#[test]
fn run_and_include_cycles_are_reported() {
    let mut host = TestHost::default();
    host.includes.insert("a.gsh".into(), "run \"b.gsh\"".into());
    host.includes
        .insert("b.gsh".into(), "include \"a.gsh\"".into());

    let error = Interpreter::new()
        .eval("run \"a.gsh\"", "main", &mut host)
        .unwrap_err();
    assert!(error.message().contains("cycle"));
    assert_eq!(error.source_name(), "b.gsh");
    assert_eq!(error.line(), 1);
    assert_eq!(error.column(), 1);
}

#[test]
fn run_preserves_loaded_source_and_host_error_locations() {
    let mut host = TestHost::default();
    host.includes
        .insert("broken.gsh".into(), "\n$missing".into());

    let loaded_error = Interpreter::new()
        .eval("run \"broken.gsh\"", "main", &mut host)
        .unwrap_err();
    assert_eq!(loaded_error.source_name(), "broken.gsh");
    assert_eq!(loaded_error.line(), 2);
    assert_eq!(loaded_error.column(), 1);

    let host_error = Interpreter::new()
        .eval("\nrun \"missing.gsh\"", "main.gsh", &mut host)
        .unwrap_err();
    assert_eq!(host_error.source_name(), "main.gsh");
    assert_eq!(host_error.line(), 2);
    assert_eq!(host_error.column(), 1);
    assert!(host_error.message().contains("missing include"));
}

#[test]
fn run_prefixed_and_non_string_forms_remain_commands() {
    let mut host = TestHost::default();
    eval("run-app file.gsh; run plain.gsh", &mut host);
    assert_eq!(
        host.calls
            .iter()
            .map(|call| call.1.as_str())
            .collect::<Vec<_>>(),
        ["run-app", "run"]
    );
    assert!(host.include_requests.is_empty());
}

#[test]
fn active_include_cycles_are_reported() {
    let mut host = TestHost::default();
    host.includes.insert("a".into(), "include \"b\"".into());
    host.includes.insert("b".into(), "include \"a\"".into());
    let error = Interpreter::new()
        .eval("include \"a\"", "main", &mut host)
        .unwrap_err();
    assert!(error.to_string().contains("include cycle"));
    assert_eq!(error.source_name(), "b");
}

#[test]
fn booleans_comparisons_and_precedence_work() {
    let mut host = TestHost::default();
    assert_eq!(
        eval("not false and 3 >= 2 or 1 == 0", &mut host),
        Value::Boolean(true)
    );
    assert_eq!(eval("\"a\" < \"b\"", &mut host), Value::Boolean(true));
    assert_eq!(eval("1 <> 2", &mut host), Value::Boolean(true));
}

#[test]
fn lists_and_value_accessors_work() {
    let mut host = TestHost::default();
    let value = eval("@[1, \"two\", true]", &mut host);
    assert_eq!(value.as_list().unwrap().len(), 3);
    assert_eq!(value.as_list().unwrap()[0].as_integer(), Some(1));
    assert_eq!(value.as_list().unwrap()[1].as_string(), Some("two"));
    assert_eq!(value.as_list().unwrap()[2].as_bool(), Some(true));
    assert!(value.is_truthy());
    assert_eq!(Value::List(vec![]).to_string(), "@[]");
}

#[test]
fn globs_are_lists_in_expressions_and_splice_in_commands() {
    let mut host = TestHost::default();
    host.globs
        .insert("*.ts".into(), vec!["a.ts".into(), "b.ts".into()]);
    host.globs
        .insert("src/**/*".into(), vec!["src/a.rs".into()]);
    let value = eval("*.ts", &mut host);
    assert_eq!(
        value,
        Value::List(vec![
            Value::String("a.ts".into()),
            Value::String("b.ts".into())
        ])
    );

    let mut interpreter = Interpreter::new();
    interpreter
        .eval("run *.ts, \"*.ts\", src/**/*", "glob", &mut host)
        .unwrap();
    assert_eq!(
        host.calls[0].2,
        vec![
            Value::String("a.ts".into()),
            Value::String("b.ts".into()),
            Value::String("*.ts".into()),
            Value::String("src/a.rs".into()),
        ]
    );
}

#[test]
fn glob_lists_can_be_iterated() {
    let mut host = TestHost::default();
    host.globs
        .insert("*.*".into(), vec!["a.txt".into(), "b.rs".into()]);
    eval("for $file in *.* do\n show $file\nend", &mut host);
    assert_eq!(host.calls.len(), 2);
    assert_eq!(host.calls[1].2, vec![Value::String("b.rs".into())]);
}

#[test]
fn errors_have_source_locations() {
    let mut host = TestHost::default();
    let error = Interpreter::new()
        .eval("\n$missing", "broken.gsh", &mut host)
        .unwrap_err();
    assert_eq!(error.source_name(), "broken.gsh");
    assert_eq!(error.line(), 2);
    assert_eq!(error.column(), 1);
    assert!(error.message().contains("unknown variable"));

    let syntax = Interpreter::new()
        .eval("@[1,", "syntax.gsh", &mut host)
        .unwrap_err();
    assert_eq!(syntax.source_name(), "syntax.gsh");
    assert!(syntax.line() >= 1);
    assert!(syntax.column() >= 1);
}

#[test]
fn source_list_call_depth_and_execution_limits_are_enforced() {
    let mut host = TestHost::default();
    let source = "x".repeat(65 * 1024);
    let error = Interpreter::new()
        .eval(&source, "large", &mut host)
        .unwrap_err();
    assert!(error.message().contains("64 KiB"));

    let values = std::iter::repeat("1")
        .take(4097)
        .collect::<Vec<_>>()
        .join(",");
    let list_source = format!("@[{values}]");
    let error = Interpreter::new()
        .eval(&list_source, "list", &mut host)
        .unwrap_err();
    assert!(error.message().contains("4096 values"));

    let recursive = "def recurse()\n recurse\nend\nrecurse";
    let error = Interpreter::new()
        .eval(recursive, "depth", &mut host)
        .unwrap_err();
    assert!(error.message().contains("call depth"));

    let endless = "$go = true\nwhile $go do\nend";
    let error = Interpreter::new()
        .eval(endless, "limit", &mut host)
        .unwrap_err();
    assert!(error.message().contains("instruction limit"));
}

#[test]
fn include_size_limit_is_enforced() {
    let mut host = TestHost::default();
    host.includes.insert("huge".into(), " ".repeat(65 * 1024));
    let error = Interpreter::new()
        .eval("include \"huge\"", "main", &mut host)
        .unwrap_err();
    assert!(error.message().contains("64 KiB"));
}
