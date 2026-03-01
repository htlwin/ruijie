# Only work on arm64 bit device and in termux app
# Only for Ruijie Network Router
import os

# GitHub ကနေ update အမြဲဆွဲချင်ရင် အောက်က line ကို uncomment လုပ်နိုင်ပါတယ်
# os.system('git pull --quiet')

if __name__ == '__main__':
    # ဒါဟာ သင် build လုပ်ထားတဲ့ starlink.so ဖိုင်ကို လှမ်းခေါ်မှာဖြစ်ပါတယ်
    import starlink
    starlink.run()
