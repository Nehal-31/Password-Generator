
# Advanced Password Generator (Tkinter)
# - Secure RNG (secrets)
# - Character set controls
# - Enforce at least one from each selected set
# - Options: exclude lookalikes, exclude custom chars, avoid repeats, avoid sequences
# - Strength meter (entropy estimate)
# - Clipboard copy
# Requires: Python 3.8+ (Tkinter included on most installs)

import tkinter as tk
from tkinter import ttk, messagebox
import string
import secrets
import math

# --- Password generation logic -------------------------------------------------

LOOKALIKE_CHARS = set('O0l1I|S5B8Z2G6q9')

def build_charsets(use_lower=True, use_upper=True, use_digits=True, use_symbols=True,
                   exclude_lookalikes=False, exclude_custom=""):
    sets = []
    if use_lower:
        sets.append(set(string.ascii_lowercase))
    if use_upper:
        sets.append(set(string.ascii_uppercase))
    if use_digits:
        sets.append(set(string.digits))
    if use_symbols:
        # A conservative, widely accepted symbol set
        sets.append(set('!@#$%^&*()-_=+[]{};:,.?/`~|\\'))

    if not sets:
        raise ValueError("Select at least one character type.")

    # Apply exclusions
    exclude = set(exclude_custom)
    if exclude_lookalikes:
        exclude |= LOOKALIKE_CHARS

    sets = [s - exclude for s in sets]
    # Remove any emptied sets (e.g., user excluded everything in a category)
    sets = [s for s in sets if s]
    if not sets:
        raise ValueError("Chosen exclusions removed all characters. Loosen your settings.")
    return sets

def has_sequence(s):
    """Return True if s contains an ascending or descending sequence of length >= 3
    for alphabetic or numeric runs (e.g., abc, 123, CBA, 987)."""
    if len(s) < 3:
        return False
    # Normalize for alpha checks
    alpha = string.ascii_lowercase
    digits = string.digits

    # Build a quick lookup for positions
    pos_alpha = {c:i for i,c in enumerate(alpha)}
    pos_digits = {c:i for i,c in enumerate(digits)}

    sl = s.lower()
    for i in range(len(s)-2):
        a,b,c = sl[i], sl[i+1], sl[i+2]
        # alpha sequences
        if a in pos_alpha and b in pos_alpha and c in pos_alpha:
            if pos_alpha[b]-pos_alpha[a]==1 and pos_alpha[c]-pos_alpha[b]==1:
                return True
            if pos_alpha[b]-pos_alpha[a]==-1 and pos_alpha[c]-pos_alpha[b]==-1:
                return True
        # digit sequences
        if s[i] in pos_digits and s[i+1] in pos_digits and s[i+2] in pos_digits:
            if pos_digits[s[i+1]]-pos_digits[s[i]]==1 and pos_digits[s[i+2]]-pos_digits[s[i+1]]==1:
                return True
            if pos_digits[s[i+1]]-pos_digits[s[i]]==-1 and pos_digits[s[i+2]]-pos_digits[s[i+1]]==-1:
                return True
    return False

def generate_password(length, use_lower, use_upper, use_digits, use_symbols,
                      exclude_lookalikes, exclude_custom, avoid_repeats, avoid_sequences):
    if length < 4:
        raise ValueError("Length should be at least 4.")

    sets = build_charsets(use_lower, use_upper, use_digits, use_symbols,
                          exclude_lookalikes, exclude_custom)
    rng = secrets.SystemRandom()

    # Guarantee at least one from each selected set
    password_chars = [rng.choice(tuple(s)) for s in sets]

    # Build pool
    pool = set().union(*sets)
    if not pool:
        raise ValueError("Character pool is empty after exclusions.")
    pool = list(pool)

    # If avoid_repeats is strict (no duplicates), ensure it's possible
    if avoid_repeats and length > len(pool):
        # Fall back to no-adjacent-repeat only
        strict_no_duplicates = False
    else:
        strict_no_duplicates = True if avoid_repeats else False

    attempts = 0
    while True:
        attempts += 1
        if attempts > 500:
            raise RuntimeError("Could not satisfy constraints. Try relaxing options.")

        # Fill remaining positions
        while len(password_chars) < length:
            ch = rng.choice(pool)
            if avoid_repeats:
                if strict_no_duplicates and ch in password_chars:
                    continue
                if not strict_no_duplicates and password_chars and ch == password_chars[-1]:
                    continue
            password_chars.append(ch)

        # Shuffle to break predictability of mandatory picks
        rng.shuffle(password_chars)
        candidate = ''.join(password_chars)

        # Apply sequence rule
        if avoid_sequences and has_sequence(candidate):
            # reset and try again
            password_chars = [rng.choice(tuple(s)) for s in sets]
            continue

        return candidate

def estimate_entropy(pw, use_lower, use_upper, use_digits, use_symbols, exclude_lookalikes, exclude_custom):
    # Estimate pool size similar to what user selected/excluded
    sets = build_charsets(use_lower, use_upper, use_digits, use_symbols, exclude_lookalikes, exclude_custom)
    pool = set().union(*sets)
    pool_size = max(len(pool), 1)
    entropy_bits = len(pw) * math.log2(pool_size)
    return entropy_bits, pool_size

def strength_label(entropy_bits):
    if entropy_bits < 45:
        return "Weak"
    elif entropy_bits < 60:
        return "Moderate"
    elif entropy_bits < 80:
        return "Strong"
    else:
        return "Very strong"

# --- GUI ----------------------------------------------------------------------

class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=16)
        master.title("Advanced Password Generator")
        master.resizable(False, False)
        self.grid(sticky="nsew")

        # Variables
        self.length = tk.IntVar(value=16)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_lookalikes = tk.BooleanVar(value=False)
        self.exclude_custom = tk.StringVar(value="")
        self.avoid_repeats = tk.BooleanVar(value=True)
        self.avoid_sequences = tk.BooleanVar(value=True)

        # Layout
        self.build_ui()

    def build_ui(self):
        # Length
        lf = ttk.LabelFrame(self, text="Length")
        lf.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        lf.columnconfigure(1, weight=1)
        ttk.Scale(lf, from_=8, to=128, variable=self.length, orient="horizontal", command=self._sync_length_from_scale).grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=6)
        self.length_entry = ttk.Spinbox(lf, from_=4, to=256, textvariable=self.length, width=6, command=self._clamp_length)
        self.length_entry.grid(row=0, column=2, sticky="e", padx=8)

        # Types
        tf = ttk.LabelFrame(self, text="Character types")
        tf.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        ttk.Checkbutton(tf, text="Lowercase (a-z)", variable=self.use_lower).grid(row=0, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(tf, text="Uppercase (A-Z)", variable=self.use_upper).grid(row=0, column=1, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(tf, text="Digits (0-9)", variable=self.use_digits).grid(row=1, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(tf, text="Symbols (!@#$…)", variable=self.use_symbols).grid(row=1, column=1, sticky="w", padx=8, pady=2)

        # Advanced
        af = ttk.LabelFrame(self, text="Advanced options")
        af.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        ttk.Checkbutton(af, text="Exclude lookalikes (O/0, l/1, I, S/5, B/8…)", variable=self.exclude_lookalikes).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(af, text="Avoid repeated characters", variable=self.avoid_repeats).grid(row=1, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(af, text="Avoid sequences (abc, 123, CBA…)", variable=self.avoid_sequences).grid(row=1, column=1, sticky="w", padx=8, pady=2)
        ttk.Label(af, text="Exclude these characters:").grid(row=2, column=0, sticky="w", padx=8, pady=(6,2))
        ttk.Entry(af, textvariable=self.exclude_custom, width=28).grid(row=2, column=1, sticky="ew", padx=8, pady=(6,2))

        # Output
        of = ttk.LabelFrame(self, text="Output")
        of.grid(row=3, column=0, sticky="ew", padx=4, pady=4)
        of.columnconfigure(0, weight=1)
        self.output = ttk.Entry(of, font=("Consolas", 12))
        self.output.grid(row=0, column=0, sticky="ew", padx=8, pady=6)

        btns = ttk.Frame(of)
        btns.grid(row=1, column=0, sticky="ew", padx=8, pady=6)
        ttk.Button(btns, text="Generate", command=self.on_generate).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Copy to clipboard", command=self.on_copy).grid(row=0, column=1, padx=4)
        ttk.Button(btns, text="Clear", command=lambda: self.output.delete(0, tk.END)).grid(row=0, column=2, padx=4)

        # Strength
        sf = ttk.Frame(of)
        sf.grid(row=2, column=0, sticky="ew", padx=8, pady=(0,8))
        ttk.Label(sf, text="Strength:").grid(row=0, column=0, sticky="w")
        self.str_label = ttk.Label(sf, text="–")
        self.str_label.grid(row=0, column=1, sticky="w", padx=(6,0))
        self.progress = ttk.Progressbar(sf, length=260, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=2, sticky="e", padx=(12,0))

    def _clamp_length(self):
        try:
            v = int(self.length.get())
        except Exception:
            v = 16
        v = max(4, min(256, v))
        self.length.set(v)

    def _sync_length_from_scale(self, _):
        # Make sure spinbox reflects the slider (already bound via variable)
        self._clamp_length()

    def on_generate(self):
        self._clamp_length()
        try:
            pw = generate_password(
                length=self.length.get(),
                use_lower=self.use_lower.get(),
                use_upper=self.use_upper.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                exclude_lookalikes=self.exclude_lookalikes.get(),
                exclude_custom=self.exclude_custom.get(),
                avoid_repeats=self.avoid_repeats.get(),
                avoid_sequences=self.avoid_sequences.get()
            )
            self.output.delete(0, tk.END)
            self.output.insert(0, pw)
            bits, pool_size = estimate_entropy(
                pw,
                self.use_lower.get(), self.use_upper.get(), self.use_digits.get(), self.use_symbols.get(),
                self.exclude_lookalikes.get(), self.exclude_custom.get()
            )
            label = f"{strength_label(bits)}  (~{bits:.1f} bits; pool={pool_size})"
            self.str_label.config(text=label)
            # Map bits to 0..100 (cap at 100)
            score = max(0, min(100, int(bits)))
            self.progress['value'] = score
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_copy(self):
        pw = self.output.get()
        if not pw:
            messagebox.showwarning("Nothing to copy", "Generate a password first.")
            return
        self.clipboard_clear()
        self.clipboard_append(pw)
        # Keep clipboard after app closes
        self.update()  # ensures the clipboard data is set
        messagebox.showinfo("Copied", "Password copied to clipboard.")


def main():
    root = tk.Tk()
    # Use ttk theme for a modern look
    try:
        style = ttk.Style()
        if 'clam' in style.theme_names():
            style.theme_use('clam')
    except Exception:
        pass
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
