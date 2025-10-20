use super::*;

#[test]
fn test_valid_flow() {
    let flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: Some(crate::model::Trigger::Single("cli.manual".to_string())),
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "step1".to_string(),
                use_: Some("core.echo".to_string()),
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&flow).is_ok());
}

#[test]
fn test_empty_name() {
    let flow = Flow {
        name: "".to_string(),
        description: None,
        version: None,
        on: None,
        cron: None,
        vars: None,
        steps: vec![],
        catch: None,
    };
    
    assert!(Validator::validate(&flow).is_err());
}

#[test]
fn test_duplicate_step_ids() {
    let flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: None,
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "step1".to_string(),
                use_: Some("core.echo".to_string()),
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            },
            Step {
                id: "step1".to_string(),
                use_: Some("core.echo".to_string()),
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&flow).is_err());
}

#[test]
fn test_parallel_without_steps() {
    let flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: None,
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "parallel_block".to_string(),
                use_: None,
                with: None,
                depends_on: None,
                parallel: Some(true),
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None, // Missing!
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&flow).is_err());
}

#[test]
fn test_foreach_without_as() {
    let flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: None,
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "foreach_block".to_string(),
                use_: None,
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: Some("{{ items }}".to_string()),
                as_: None, // Missing!
                do_: Some(vec![]),
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&flow).is_err());
}

#[test]
fn test_invalid_identifier() {
    let flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: None,
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "123invalid".to_string(), // Starts with number!
                use_: Some("core.echo".to_string()),
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&flow).is_err());
}

#[test]
fn test_json_schema_validation() {
    // Valid flow should pass schema validation
    let valid_flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: Some(crate::model::Trigger::Single("cli.manual".to_string())),
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "step1".to_string(),
                use_: Some("core.echo".to_string()),
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&valid_flow).is_ok());
}

#[test]
fn test_schema_validation_missing_step_action() {
    // Step without use, parallel, foreach, await_event, or wait should fail
    let invalid_flow = Flow {
        name: "test".to_string(),
        description: None,
        version: None,
        on: Some(crate::model::Trigger::Single("cli.manual".to_string())),
        cron: None,
        vars: None,
        steps: vec![
            Step {
                id: "step1".to_string(),
                use_: None, // Missing action!
                with: None,
                depends_on: None,
                parallel: None,
                if_: None,
                foreach: None,
                as_: None,
                do_: None,
                steps: None,
                retry: None,
                await_event: None,
                wait: None,
            }
        ],
        catch: None,
    };
    
    assert!(Validator::validate(&invalid_flow).is_err());
}
