"""
PassGPT-based password generator.

Uses pre-trained or fine-tuned PassGPT model to generate passwords
in approximate descending probability order.
"""

import argparse
import torch
from pathlib import Path
from typing import Optional, List
from transformers import GPT2LMHeadModel, RobertaTokenizerFast


class PassGPTGenerator:
    """
    Password generator using PassGPT (GPT-2 trained on password leaks).
    
    Can use pre-trained HuggingFace model or fine-tuned local model.
    """
    
    # Use Brazilian fine-tuned model by default, fall back to earlier versions
    DEFAULT_MODEL = "brgen/models/brazilian-passgpt-v3"
    FALLBACK_MODEL = "brgen/models/brazilian-passgpt-v2"  # v2 if v3 not found
    MAX_CHARS = 10
    
    def __init__(self, model_path: Optional[str] = None, device: Optional[str] = None):
        """
        Initialize generator.
        
        Args:
            model_path: Path to local model or HuggingFace model ID
            device: 'cuda', 'cpu', or None for auto-detect
        """
        if model_path:
            self.model_path = model_path
        else:
            # Use Brazilian model if it exists, otherwise fallback
            if Path(self.DEFAULT_MODEL).exists():
                self.model_path = self.DEFAULT_MODEL
            else:
                self.model_path = self.FALLBACK_MODEL
        
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._model = None
        self._tokenizer = None
        
    @property
    def tokenizer(self):
        """Lazy-load tokenizer."""
        if self._tokenizer is None:
            self._tokenizer = RobertaTokenizerFast.from_pretrained(
                self.model_path,
                max_len=self.MAX_CHARS + 2,  # Max length + start and end tokens
                padding="max_length",
                truncation=True,
                do_lower_case=False,
                strip_accents=False,
                mask_token="<mask>",
                unk_token="<unk>",
                pad_token="<pad>",
                truncation_side="right"
            )
        return self._tokenizer
    
    @property
    def model(self):
        """Lazy-load model."""
        if self._model is None:
            self._model = GPT2LMHeadModel.from_pretrained(self.model_path)
            self._model = self._model.to(self.device).eval()
        return self._model
    
    def generate(
        self,
        count: int = 100,
        temperature: float = 1.0,
        top_k: int = 50,
        top_p: float = 0.95,
        batch_size: int = 256,
        deduplicate: bool = True,
        min_length: int = 1,
        verbose: bool = True
    ) -> List[str]:
        """
        Generate passwords.
        
        Args:
            count: Number of unique passwords to generate
            temperature: Sampling temperature (higher = more random)
            top_k: Top-k sampling parameter
            top_p: Nucleus sampling parameter
            batch_size: Batch size for generation
            deduplicate: Remove duplicate passwords
            min_length: Minimum password length (8 for WPA)
            verbose: Show progress
            
        Returns:
            List of generated passwords
        """
        passwords = []
        seen = set()
        stale_rounds = 0  # Track rounds with no new passwords
        max_stale_rounds = 20  # Stop if we can't find new passwords
        
        with torch.no_grad():
            while len(passwords) < count and stale_rounds < max_stale_rounds:
                # Generate batch - larger batches for efficiency
                current_batch = min(batch_size, 512)
                prev_count = len(passwords)
                
                input_ids = torch.tensor([[self.tokenizer.bos_token_id]] * current_batch).to(self.device)
                
                outputs = self.model.generate(
                    input_ids,
                    do_sample=True,
                    num_return_sequences=1,
                    max_length=self.MAX_CHARS + 2,
                    pad_token_id=self.tokenizer.pad_token_id,
                    bad_words_ids=[[self.tokenizer.bos_token_id]],
                    temperature=temperature,
                    top_k=top_k,
                    top_p=top_p,
                )
                
                # Remove BOS token and decode
                outputs = outputs[:, 1:]
                decoded = self.tokenizer.batch_decode(outputs.tolist())
                
                # Clean up - get content before EOS token
                for pwd in decoded:
                    clean = pwd.split("</s>")[0].strip()
                    if clean and len(clean) >= min_length and (not deduplicate or clean not in seen):
                        seen.add(clean)
                        passwords.append(clean)
                
                # Track progress
                new_count = len(passwords) - prev_count
                if new_count == 0:
                    stale_rounds += 1
                else:
                    stale_rounds = 0
                
                # Progress output
                if verbose and len(passwords) % 1000 < current_batch:
                    print(f"  Generated {len(passwords):,}/{count:,} unique passwords...")
                
        if len(passwords) < count:
            print(f"  Warning: Could only generate {len(passwords):,} unique passwords (model may need higher temperature)")
                
        return passwords[:count]
    
    def generate_to_file(
        self,
        output_path: str,
        count: int = 10000,
        **kwargs
    ) -> int:
        """
        Generate passwords and write to file.
        
        Args:
            output_path: Path to output file
            count: Number of passwords to generate
            **kwargs: Additional args passed to generate()
            
        Returns:
            Number of passwords written
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"Generating {count} passwords with {self.model_path}...")
        print(f"Device: {self.device}")
        
        passwords = self.generate(count=count, **kwargs)
        
        with open(output, 'w') as f:
            for pwd in passwords:
                f.write(pwd + '\n')
        
        print(f"Wrote {len(passwords)} passwords to {output_path}")
        return len(passwords)
    
    def _score_sequence(self, token_ids: torch.Tensor) -> float:
        """
        Calculate log probability of a token sequence.
        
        Args:
            token_ids: Token IDs including BOS token
            
        Returns:
            Log probability (sum of log probs for each token)
        """
        with torch.no_grad():
            outputs = self.model(token_ids.unsqueeze(0))
            logits = outputs.logits[0, :-1, :]  # Exclude last position
            log_probs = torch.log_softmax(logits, dim=-1)
            
            # Get log prob of each actual next token
            target_ids = token_ids[1:]  # Exclude BOS
            token_log_probs = log_probs.gather(1, target_ids.unsqueeze(1)).squeeze()
            
            return token_log_probs.sum().item()
    
    def generate_ordered(
        self,
        count: int = 100,
        top_k_per_step: int = 20,
        min_log_prob: float = -50.0,
        min_length: int = 1,
        batch_size: int = 64,
        verbose: bool = True
    ) -> List[tuple]:
        """
        Generate passwords in exact descending probability order using best-first search.
        
        Uses a priority queue (heap) to always expand the highest-probability
        incomplete sequence. This is the proper SOPG approach - no beam width
        limits the exploration, only a probability threshold.
        
        Args:
            count: Number of unique passwords to generate
            top_k_per_step: How many next tokens to consider at each expansion
            min_log_prob: Stop exploring sequences below this log probability
            min_length: Minimum password length (8 for WPA)
            batch_size: Process this many sequences at once for GPU efficiency
            verbose: Show progress
            
        Returns:
            List of (password, log_probability) tuples in descending probability order
        """
        import heapq
        
        results = []
        seen = set()
        
        bos_id = self.tokenizer.bos_token_id
        eos_id = self.tokenizer.eos_token_id
        
        # Priority queue: (-log_prob, sequence_tokens)
        # Negative because heapq is a min-heap, we want max probability first
        # Each item: (-cumulative_log_prob, token_list)
        heap = [(-0.0, [bos_id])]
        
        expansions = 0
        
        if verbose:
            print(f"Best-first search (top_k={top_k_per_step}, min_prob={min_log_prob})...")
        
        with torch.no_grad():
            while heap and len(results) < count:
                # Get the highest probability incomplete sequence
                neg_cum_prob, tokens = heapq.heappop(heap)
                cum_prob = -neg_cum_prob
                
                # Skip if probability too low
                if cum_prob < min_log_prob:
                    continue
                
                # Get next token distribution
                input_tensor = torch.tensor([tokens], device=self.device)
                outputs = self.model(input_tensor)
                next_logits = outputs.logits[0, -1, :]
                log_probs = torch.log_softmax(next_logits, dim=-1)
                
                # Get top-k next tokens
                top_log_probs, top_indices = log_probs.topk(top_k_per_step)
                
                for i in range(top_k_per_step):
                    next_token = top_indices[i].item()
                    next_log_prob = top_log_probs[i].item()
                    new_cum_prob = cum_prob + next_log_prob
                    
                    # Skip if below threshold
                    if new_cum_prob < min_log_prob:
                        continue
                    
                    if next_token == eos_id:
                        # Complete password - extract and store
                        pwd_tokens = tokens[1:]  # Remove BOS
                        if pwd_tokens:
                            pwd = self.tokenizer.decode(pwd_tokens)
                            pwd = pwd.split("</s>")[0].split("<pad>")[0].strip()
                            
                            if pwd and len(pwd) >= min_length and pwd not in seen:
                                seen.add(pwd)
                                results.append((pwd, new_cum_prob))
                                
                                if verbose and len(results) % 1000 == 0:
                                    print(f"  {len(results):,} passwords, heap size: {len(heap):,}, prob: {new_cum_prob:.2f}")
                    else:
                        # Add extended sequence back to heap
                        if len(tokens) < self.MAX_CHARS + 1:  # +1 for BOS
                            new_tokens = tokens + [next_token]
                            heapq.heappush(heap, (-new_cum_prob, new_tokens))
                
                expansions += 1
                
                # Progress update
                if verbose and expansions % 10000 == 0:
                    print(f"  Expansions: {expansions:,}, passwords: {len(results):,}, heap: {len(heap):,}")
                
                # Memory guard - if heap gets too large, prune low-probability entries
                if len(heap) > 1_000_000:
                    if verbose:
                        print(f"  Pruning heap from {len(heap):,}...")
                    # Keep top half by probability
                    heap = heapq.nsmallest(500_000, heap)
                    heapq.heapify(heap)
        
        # Already in probability order due to best-first search
        if verbose:
            print(f"  Complete: {len(results)} passwords after {expansions:,} expansions")
        
        return results[:count]

    
    def generate_ordered_to_file(
        self,
        output_path: str,
        count: int = 10000,
        flush_interval: int = 120,  # seconds
        flush_count: int = 5000,    # passwords
        **kwargs
    ) -> int:
        """
        Generate probability-ordered passwords and write to file incrementally.
        
        Writes progress to a .partial file, renaming to final path when complete.
        Flushes to disk every flush_interval seconds or flush_count passwords.
        
        Args:
            output_path: Path to output file
            count: Number of passwords to generate
            flush_interval: Seconds between disk writes (default 120)
            flush_count: Passwords between disk writes (default 5000)
            **kwargs: Additional args passed to generate_ordered()
            
        Returns:
            Number of passwords written
        """
        import time
        import heapq
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        # Use partial filename during generation
        partial_path = output.with_suffix(output.suffix + '.partial')
        
        print(f"Generating {count} ordered passwords with {self.model_path}...")
        print(f"Device: {self.device}")
        print(f"Output: {partial_path} (will rename when complete)")
        
        # Get params
        top_k_per_step = kwargs.get('top_k_per_step', 20)
        min_log_prob = kwargs.get('min_log_prob', -50.0)
        min_length = kwargs.get('min_length', 1)
        verbose = kwargs.get('verbose', True)
        
        results = []
        seen = set()
        
        bos_id = self.tokenizer.bos_token_id
        eos_id = self.tokenizer.eos_token_id
        
        heap = [(-0.0, [bos_id])]
        expansions = 0
        last_flush_time = time.time()
        last_flush_count = 0
        
        if verbose:
            print(f"Best-first search (top_k={top_k_per_step}, min_prob={min_log_prob})...")
        
        # Open file for incremental writing
        with open(partial_path, 'w') as f:
            with torch.no_grad():
                while heap and len(results) < count:
                    neg_cum_prob, tokens = heapq.heappop(heap)
                    cum_prob = -neg_cum_prob
                    
                    if cum_prob < min_log_prob:
                        continue
                    
                    input_tensor = torch.tensor([tokens], device=self.device)
                    outputs = self.model(input_tensor)
                    next_logits = outputs.logits[0, -1, :]
                    log_probs = torch.log_softmax(next_logits, dim=-1)
                    
                    top_log_probs, top_indices = log_probs.topk(top_k_per_step)
                    
                    for i in range(top_k_per_step):
                        next_token = top_indices[i].item()
                        next_log_prob = top_log_probs[i].item()
                        new_cum_prob = cum_prob + next_log_prob
                        
                        if new_cum_prob < min_log_prob:
                            continue
                        
                        if next_token == eos_id:
                            pwd_tokens = tokens[1:]
                            if pwd_tokens:
                                pwd = self.tokenizer.decode(pwd_tokens)
                                pwd = pwd.split("</s>")[0].split("<pad>")[0].strip()
                                
                                if pwd and len(pwd) >= min_length and pwd not in seen:
                                    seen.add(pwd)
                                    results.append((pwd, new_cum_prob))
                                    f.write(pwd + '\n')
                                    
                                    if verbose and len(results) % 1000 == 0:
                                        pct = int(100 * len(results) / count)
                                        print(f"  {len(results):,} ({pct}%), heap: {len(heap):,}, prob: {new_cum_prob:.2f}")
                        else:
                            if len(tokens) < self.MAX_CHARS + 1:
                                new_tokens = tokens + [next_token]
                                heapq.heappush(heap, (-new_cum_prob, new_tokens))
                    
                    expansions += 1
                    
                    # Periodic flush to disk
                    now = time.time()
                    new_passwords = len(results) - last_flush_count
                    if new_passwords >= flush_count or (now - last_flush_time) >= flush_interval:
                        f.flush()
                        pct = int(100 * len(results) / count)
                        if verbose:
                            print(f"  💾 Flushed {len(results):,} passwords ({pct}%) to disk")
                        last_flush_time = now
                        last_flush_count = len(results)
                    
                    # Memory guard
                    if len(heap) > 1_000_000:
                        if verbose:
                            print(f"  Pruning heap from {len(heap):,}...")
                        heap = heapq.nsmallest(500_000, heap)
                        heapq.heapify(heap)
        
        # Rename to final path
        partial_path.rename(output)
        
        if verbose:
            print(f"  ✅ Complete: {len(results)} passwords after {expansions:,} expansions")
            print(f"  Saved to: {output_path}")
        
        return len(results)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Generate passwords with PassGPT")
    parser.add_argument("--model", "-m", default=None,
                        help="Model path (default: brgen/models/brazilian-passgpt)")
    parser.add_argument("--output", "-o", default="brgen/output/passwords.txt",
                        help="Output file path")
    parser.add_argument("--count", "-n", type=int, default=1000,
                        help="Number of passwords to generate")
    parser.add_argument("--min-length", type=int, default=1,
                        help="Minimum password length (use 8 for WPA)")
    parser.add_argument("--temperature", "-t", type=float, default=1.0,
                        help="Sampling temperature (random mode only)")
    parser.add_argument("--top-k", type=int, default=50,
                        help="Top-k sampling (random mode only)")
    parser.add_argument("--top-p", type=float, default=0.95,
                        help="Nucleus sampling (random mode only)")
    parser.add_argument("--batch-size", "-b", type=int, default=256,
                        help="Batch size for generation")
    parser.add_argument("--device", "-d", default=None,
                        help="Device: cuda, cpu, or auto")
    parser.add_argument("--ordered", action="store_true",
                        help="Use best-first search for probability-ordered output")
    parser.add_argument("--top-k-per-step", type=int, default=20,
                        help="Tokens to consider per expansion (ordered mode)")
    parser.add_argument("--min-log-prob", type=float, default=-50.0,
                        help="Min log probability threshold (ordered mode)")
    
    args = parser.parse_args()
    
    generator = PassGPTGenerator(model_path=args.model, device=args.device)
    
    if args.ordered:
        generator.generate_ordered_to_file(
            args.output,
            count=args.count,
            top_k_per_step=args.top_k_per_step,
            min_log_prob=args.min_log_prob,
            min_length=args.min_length,
        )
    else:
        generator.generate_to_file(
            args.output,
            count=args.count,
            temperature=args.temperature,
            top_k=args.top_k,
            top_p=args.top_p,
            batch_size=args.batch_size,
            min_length=args.min_length,
        )


if __name__ == "__main__":
    main()

