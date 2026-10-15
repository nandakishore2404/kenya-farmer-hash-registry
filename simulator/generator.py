import random
import json
import os
from typing import Dict, List, Any

# Counties in Kenya: 047 (Nairobi), 032 (Nakuru), 019 (Nyeri), 042 (Kisumu)
COUNTIES = ["047", "032", "019", "042"]
GENDERS = ["F", "M"]
AGE_BANDS = ["18-24", "25-34", "35-44", "45-54", "55-64", "65+"]
PARTNERS = ["test_partner_a", "test_partner_b", "test_partner_c"]

def generate_kenyan_number(prefix_choice: str = None) -> str:
    """Generates an 8-digit suffix following 7 or 1 prefix."""
    if prefix_choice is None:
        prefix_choice = random.choice(["7", "1"])
    suffix = "".join(random.choices("0123456789", k=8))
    return f"{prefix_choice}{suffix}"

def format_phone_variant(nine_digits: str) -> str:
    """Applies one of the mixed real-world formatting styles."""
    style = random.choice([
        "local_0",        # 0712345678
        "int_no_plus",    # 254712345678
        "int_plus",       # +254712345678
        "spaces",         # +254 712 345 678
        "parentheses",    # +254 (712) 345-678
        "dashes",         # 0712-345-678
        "raw_9"           # 712345678
    ])
    p = nine_digits
    if style == "local_0":
        return f"0{p}"
    elif style == "int_no_plus":
        return f"254{p}"
    elif style == "int_plus":
        return f"+254{p}"
    elif style == "spaces":
        return f"+254 {p[0:3]} {p[3:6]} {p[6:]}"
    elif style == "parentheses":
        return f"+254 ({p[0:3]}) {p[3:6]}-{p[6:]}"
    elif style == "dashes":
        return f"0{p[0:3]}-{p[3:6]}-{p[6:]}"
    else:
        return p

def generate_synthetic_dataset(total_farmers: int = 3000, seed: int = 42) -> Dict[str, Any]:
    random.seed(seed)
    
    # Target allocations
    # 5% shared phones = 150 people (75 pairs sharing phone)
    # 3% second SIMs = 90 people (each having 2 numbers)
    # 12% 2-partner overlap = 360 farmers
    # 3% 3-partner overlap = 90 farmers
    # 85% 1-partner = 2,550 farmers
    
    individuals = []
    
    # 1. Base pool of individuals
    for i in range(total_farmers):
        ind = {
            "individual_id": f"farmer_{i+1:04d}",
            "gender": random.choice(GENDERS),
            "age_band": random.choice(AGE_BANDS),
            "county_code": random.choice(COUNTIES),
            "primary_phone_digits": generate_kenyan_number(),
            "secondary_phone_digits": None,
            "shares_phone_with": None
        }
        individuals.append(ind)
        
    # 2. Inject 5% shared household phones (75 pairs = 150 individuals)
    shared_count = int(total_farmers * 0.05)
    # Pair up first shared_count individuals
    for i in range(0, shared_count, 2):
        ind_a = individuals[i]
        ind_b = individuals[i+1]
        
        # Share phone number, ensure different demographics
        shared_digits = ind_a["primary_phone_digits"]
        ind_b["primary_phone_digits"] = shared_digits
        ind_b["gender"] = "M" if ind_a["gender"] == "F" else "F"
        ind_b["age_band"] = random.choice([b for b in AGE_BANDS if b != ind_a["age_band"]])
        ind_a["shares_phone_with"] = ind_b["individual_id"]
        ind_b["shares_phone_with"] = ind_a["individual_id"]

    # 3. Inject 3% second SIM cards (90 individuals)
    second_sim_count = int(total_farmers * 0.03)
    second_sim_indices = range(shared_count, shared_count + second_sim_count)
    for idx in second_sim_indices:
        individuals[idx]["secondary_phone_digits"] = generate_kenyan_number()

    # 4. Assign partner overlaps
    # Shuffle for partner assignment
    indices = list(range(total_farmers))
    random.shuffle(indices)
    
    three_partner_count = int(total_farmers * 0.03) # 90
    two_partner_count = int(total_farmers * 0.12)   # 360
    
    three_partner_idx = set(indices[:three_partner_count])
    two_partner_idx = set(indices[three_partner_count:three_partner_count + two_partner_count])
    one_partner_idx = set(indices[three_partner_count + two_partner_count:])
    
    partner_events = []
    
    for idx, ind in enumerate(individuals):
        if idx in three_partner_idx:
            assigned_partners = ["test_partner_a", "test_partner_b", "test_partner_c"]
        elif idx in two_partner_idx:
            assigned_partners = random.sample(PARTNERS, 2)
        else:
            assigned_partners = [random.choice(PARTNERS)]
            
        for p_idx, partner_id in enumerate(assigned_partners):
            # If farmer has a second SIM and is registered by multiple partners,
            # simulate them registering with partner B using their second SIM
            phone_to_use = ind["primary_phone_digits"]
            if p_idx > 0 and ind["secondary_phone_digits"] is not None:
                phone_to_use = ind["secondary_phone_digits"]
                
            formatted_phone = format_phone_variant(phone_to_use)
            partner_events.append({
                "individual_id": ind["individual_id"],
                "partner_id": partner_id,
                "raw_phone": formatted_phone,
                "phone_digits": phone_to_use,
                "gender": ind["gender"],
                "age_band": ind["age_band"],
                "county_code": ind["county_code"],
                "is_csv_upload": (partner_id == "test_partner_c")
            })

    # 5. Inject 1% consent withdrawals
    withdrawal_count = max(1, int(len(partner_events) * 0.01))
    withdrawal_events = random.sample(partner_events, withdrawal_count)

    return {
        "summary": {
            "true_unique_individuals": total_farmers,
            "shared_phone_individuals": shared_count,
            "shared_phone_pairs": shared_count // 2,
            "second_sim_individuals": second_sim_count,
            "total_partner_registrations": len(partner_events),
            "planned_withdrawals": withdrawal_count
        },
        "individuals": individuals,
        "registrations": partner_events,
        "withdrawals": withdrawal_events
    }

if __name__ == "__main__":
    data = generate_synthetic_dataset()
    out_dir = os.path.dirname(__file__)
    gt_path = os.path.join(out_dir, "ground_truth.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {data['summary']['total_partner_registrations']} registration events for {data['summary']['true_unique_individuals']} true individuals.")
    print(f"Saved to {gt_path}")
