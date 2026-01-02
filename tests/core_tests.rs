#[cfg(test)]
mod tests {
    use processvision::core::process_enum::enumerate_processes;

    #[test]
    fn test_process_enumeration() {
        let procs = enumerate_processes();
        assert!(procs.is_ok());
        let procs = procs.unwrap();
        assert!(!procs.is_empty());

        // Check if current process is in the list (or at least PID 0 is not the only one)
        assert!(procs.iter().any(|p| p.pid != 0));
    }
}
