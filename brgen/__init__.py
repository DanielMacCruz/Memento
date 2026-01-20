"""
Brazilian Password Generator (brgen)

PassGPT-based password generation for Brazilian passwords.

Quick Start:
    # Generate passwords with pre-trained model
    python -m brgen.passgpt_generator --count 1000 --output brgen/output/passwords.txt

    # Fine-tune on Brazilian passwords
    python -m brgen.finetune --input wordlists/0xc0da-ptbr.txt

    # Generate with fine-tuned model
    python -m brgen.passgpt_generator --model brgen/models/brazilian-passgpt --count 1000
"""

from .passgpt_generator import PassGPTGenerator
