"""
Fine-tune PassGPT on Brazilian passwords.

Adapts pre-trained PassGPT to Brazilian password patterns.
"""

import argparse
import os
from pathlib import Path
from typing import Optional

import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    GPT2LMHeadModel,
    RobertaTokenizerFast,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling,
)


class PasswordDataset(Dataset):
    """Dataset of passwords for fine-tuning."""
    
    def __init__(self, passwords: list, tokenizer, max_length: int = 12):
        self.passwords = passwords
        self.tokenizer = tokenizer
        self.max_length = max_length
        
    def __len__(self):
        return len(self.passwords)
    
    def __getitem__(self, idx):
        password = self.passwords[idx]
        # Tokenize with BOS and EOS
        encoding = self.tokenizer(
            password,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        # Squeeze to remove batch dimension
        return {
            "input_ids": encoding["input_ids"].squeeze(),
            "attention_mask": encoding["attention_mask"].squeeze(),
        }


def load_passwords(file_path: str, max_length: int = 10) -> list:
    """
    Load passwords from file, filtering by max length.
    
    Args:
        file_path: Path to password file (one per line)
        max_length: Maximum password length to include
        
    Returns:
        List of passwords
    """
    passwords = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pwd = line.strip()
            if pwd and len(pwd) <= max_length:
                passwords.append(pwd)
    
    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for pwd in passwords:
        if pwd not in seen:
            seen.add(pwd)
            unique.append(pwd)
    
    return unique


def finetune(
    input_file: str,
    output_dir: str = "brgen/models/brazilian-passgpt",
    base_model: str = "javirandor/passgpt-10characters",
    epochs: int = 3,
    batch_size: int = 32,
    learning_rate: float = 5e-5,
    max_length: int = 10,
    device: Optional[str] = None
):
    """
    Fine-tune PassGPT on a password dataset.
    
    Args:
        input_file: Path to password file
        output_dir: Directory to save fine-tuned model
        base_model: Base model to fine-tune
        epochs: Number of training epochs
        batch_size: Training batch size
        learning_rate: Learning rate
        max_length: Maximum password length
        device: Device to use (cuda/cpu/auto)
    """
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading base model: {base_model}")
    print(f"Device: {device}")
    
    # Load tokenizer and model
    tokenizer = RobertaTokenizerFast.from_pretrained(
        base_model,
        max_len=max_length + 2,
        padding="max_length",
        truncation=True,
        do_lower_case=False,
        strip_accents=False,
        mask_token="<mask>",
        unk_token="<unk>",
        pad_token="<pad>",
        truncation_side="right"
    )
    
    model = GPT2LMHeadModel.from_pretrained(base_model)
    
    # Load passwords
    print(f"Loading passwords from {input_file}")
    passwords = load_passwords(input_file, max_length=max_length)
    print(f"Loaded {len(passwords)} unique passwords (max {max_length} chars)")
    
    if len(passwords) < 100:
        print("Warning: Very small dataset, results may be poor")
    
    # Split into train/val
    split_idx = int(len(passwords) * 0.95)
    train_passwords = passwords[:split_idx]
    val_passwords = passwords[split_idx:]
    
    print(f"Train: {len(train_passwords)}, Val: {len(val_passwords)}")
    
    # Create datasets
    train_dataset = PasswordDataset(train_passwords, tokenizer, max_length + 2)
    val_dataset = PasswordDataset(val_passwords, tokenizer, max_length + 2)
    
    # Data collator for causal LM
    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer,
        mlm=False  # Causal LM, not masked
    )
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=str(output_path),
        overwrite_output_dir=True,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        learning_rate=learning_rate,
        weight_decay=0.01,
        logging_dir=str(output_path / "logs"),
        logging_steps=100,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        save_total_limit=2,
        fp16=torch.cuda.is_available(),  # Use mixed precision on GPU
        report_to="none",  # Disable wandb etc
    )
    
    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=data_collator,
    )
    
    # Train
    print("Starting fine-tuning...")
    trainer.train()
    
    # Save
    print(f"Saving model to {output_dir}")
    trainer.save_model(str(output_path))
    tokenizer.save_pretrained(str(output_path))
    
    print("Done! Use the model with:")
    print(f"  python -m brgen.passgpt_generator --model {output_dir} --count 1000")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Fine-tune PassGPT on passwords")
    parser.add_argument("--input", "-i", required=True,
                        help="Input password file")
    parser.add_argument("--output", "-o", default="brgen/models/brazilian-passgpt",
                        help="Output directory for fine-tuned model")
    parser.add_argument("--base-model", default="javirandor/passgpt-10characters",
                        help="Base model to fine-tune")
    parser.add_argument("--epochs", "-e", type=int, default=3,
                        help="Number of training epochs")
    parser.add_argument("--batch-size", "-b", type=int, default=32,
                        help="Training batch size")
    parser.add_argument("--learning-rate", "-lr", type=float, default=5e-5,
                        help="Learning rate")
    parser.add_argument("--max-length", type=int, default=10,
                        help="Maximum password length")
    parser.add_argument("--device", "-d", default=None,
                        help="Device: cuda, cpu, or auto")
    
    args = parser.parse_args()
    
    finetune(
        input_file=args.input,
        output_dir=args.output,
        base_model=args.base_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_length=args.max_length,
        device=args.device
    )


if __name__ == "__main__":
    main()
