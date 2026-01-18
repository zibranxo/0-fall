import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    BitsAndBytesConfig,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
)
from trl import SFTTrainer

# ===================== CONFIG =====================

MODEL_ID = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
DATA_FILE = "train.json"
OUTPUT_DIR = "llama-recon-lora"

MAX_LENGTH = 256
BATCH_SIZE = 4
GRAD_ACCUM_STEPS = 4
EPOCHS = 5
LEARNING_RATE = 1e-4

# ===================== TOKENIZER =====================

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, legacy=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.model_max_length = MAX_LENGTH

# ===================== 4-BIT CONFIG =====================

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.float16,
)

# ===================== LOAD MODEL =====================

print("Loading model...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config=bnb_config,
    device_map="auto",
    use_safetensors=True,
)

# 🔑 FORCE FP16 (prevents BF16 AMP crash)
#model.config.torch_dtype = torch.float16

# ===================== QLORA PREP =====================

model = prepare_model_for_kbit_training(model)
model.enable_input_require_grads()
model.gradient_checkpointing_enable()

# ===================== LORA CONFIG =====================

lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# ===================== LOAD DATA =====================

print("Loading dataset...")
dataset = load_dataset("json", data_files=DATA_FILE)
dataset = dataset["train"].train_test_split(test_size=0.1, seed=42)

def formatting_prompt(example):
    return f"""### Instruction:
{example['instruction']}

### Input:
{example['input']}

### Response:
{example['output']}"""

# ===================== TRAINING ARGS =====================

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=2,
    gradient_accumulation_steps=GRAD_ACCUM_STEPS,
    num_train_epochs=EPOCHS,
    learning_rate=LEARNING_RATE,
    warmup_steps=100,
    weight_decay=0.01,
    max_grad_norm=0.0,

    fp16=False,
    bf16=False,
    gradient_checkpointing=True,

    logging_steps=25,
    save_strategy="epoch",
    eval_strategy="epoch",
    save_total_limit=3,

    load_best_model_at_end=True,
    metric_for_best_model="eval_loss",
    greater_is_better=False,

    report_to="none",
    optim="paged_adamw_8bit",
)

# ===================== SFT TRAINER (LEGACY SAFE) =====================

trainer = SFTTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset["train"],
    eval_dataset=dataset["test"],
    formatting_func=formatting_prompt,
)

# ===================== TRAIN =====================

print("🚀 Starting training...")
trainer.train()

# ===================== SAVE =====================

print("Saving final model...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

print("✅ Training complete.")
