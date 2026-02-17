rule tcb212735rule1
{
  strings:
    $test_string= "smoke test"
  condition:
    $test_string
}

rule tcb212735rule2
{
	strings:
        $ = "12345" nocase wide ascii
        $ = "67890" nocase wide ascii                
        $ = {00 01 02 03 04 05}
	condition:
		any of ($*)
}

rule tcb212735rule3 {
  strings:
    $test_string= "asdf jkla"
  condition:
    $test_string
}

