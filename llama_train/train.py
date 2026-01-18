import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    BitsAndBytesConfig,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
)

# ===================== CONFIG =====================

MODEL_ID = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"   # SAFETENSORS MODEL
DATA_FILE = "train.json"
OUTPUT_DIR = "llama-recon-lora"

MAX_LENGTH = 512
BATCH_SIZE = 1
GRAD_ACCUM_STEPS = 16
EPOCHS = 5
LEARNING_RATE = 2e-4

# ===================== TOKENIZER =====================

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(
    MODEL_ID,
    legacy=True
)
tokenizer.pad_token = tokenizer.eos_token

# ===================== 4-BIT CONFIG =====================

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.float16,
)

# ===================== LOAD MODEL =====================

print("Loading model in 4-bit (safetensors)...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config=bnb_config,
    device_map="auto",
    use_safetensors=True,   # 🔒 CRITICAL
)

# ===================== QLORA PREP =====================

print("Preparing model for k-bit training...")
model = prepare_model_for_kbit_training(model)

# Required when using gradient checkpointing + QLoRA
model.enable_input_require_grads()

# ===================== LORA CONFIG =====================

print("Attaching LoRA adapters...")
lora_config = LoraConfig(
    r=4,
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

def tokenize(example):
    text = f"""### Instruction:
{example['instruction']}

### Input:
{example['input']}

### Response:
{example['output']}"""

    out = tokenizer(
        text,
        truncation=True,
        padding="max_length",
        max_length=MAX_LENGTH,
    )

    # Reconstruction loss
    out["labels"] = out["input_ids"]
    return out

print("Tokenizing dataset...")
tokenized_dataset = dataset.map(
    tokenize,
    remove_columns=dataset["train"].column_names,
    desc="Tokenizing",
)

# ===================== TRAINING =====================

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=BATCH_SIZE,
    gradient_accumulation_steps=GRAD_ACCUM_STEPS,
    num_train_epochs=EPOCHS,
    learning_rate=LEARNING_RATE,
    fp16=True,
    gradient_checkpointing=True,

    logging_strategy="steps",
    logging_steps=50,

    save_strategy="epoch",        # ✅ SAVE EACH EPOCH
    save_total_limit=5,
    save_safetensors=True,        # 🔒 NO torch.load

    report_to="none",
    optim="paged_adamw_8bit",
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset["train"],
)

# ===================== TRAIN =====================

print("Starting training...")
trainer.train()

# ===================== SAVE FINAL =====================

print("Saving final LoRA adapter...")
model.save_pretrained(
    OUTPUT_DIR,
    safe_serialization=True
)
tokenizer.save_pretrained(OUTPUT_DIR)

print("Training complete.")
