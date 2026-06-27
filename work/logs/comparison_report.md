# Route Comparison

| Route | Detection Rate | Confirmed Detection Rate | Time (s) | CPU (s) | Avg CPU % | Max RSS (KB) | False Positives | Raw Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| LLM Fuzzer | 83.33% | 50.00% | 43.377268 | 0.836672 | 1.93% | 107452 | 2 | /work/logs/llm_fuzzer_result.json |
| boofuzz | 66.67% | 66.67% | 0.600668 | 0.613296 | 102.10% | 107452 | 0 | /work/logs/boofuzz_result.json |

## Notes

- LLM Fuzzer detection is based on LLM candidates matched to the ground truth.
- LLM Fuzzer confirmation is based on reproduced findings linked to LLM-generated seed files.
- boofuzz detection is based on reproduced findings linked to boofuzz field metadata.
- Only CONFIRMED execution evidence should be treated as final vulnerabilities.
