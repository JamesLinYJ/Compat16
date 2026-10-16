use super::*;

pub(super) fn template() -> Win16HostDialogTemplate {
    Win16HostDialogTemplate {
        style: 0x8000_0000, x: 0, y: 0, width: 40, height: 40,
        menu: Atom::None, menu_template: None, class: Atom::None, guest_class_name: None,
        title: Atom::None, font: None,
        items: vec![runtime::Win16HostDialogItem {
            style: 0x4000_0003, x: 0, y: 0, width: 16, height: 16, id: 0xffff,
            class: Atom::Ordinal(0x82), guest_class_name: None, title: Atom::None,
            initial_icon: Some(runtime::Win16HostIcon(1)), creation_data: Vec::new(),
        }],
    }
}
#[test]
fn dialog_icon_eligibility_accepts_duplicate_ids_and_standard_roots() {
    let mut template = template();
    template.items.push(template.items[0].clone());
    assert!(eligible(&template));
    template.class = Atom::Ordinal(0x8002);
    assert!(eligible(&template));
}
#[test]
fn dialog_icon_eligibility_rejects_custom_or_named_siblings_and_root() {
    let mut template = template();
    template.items.push(template.items[0].clone());
    template.items[1].initial_icon = None;
    template.items[1].class = Atom::String(b"STATIC".to_vec());
    assert!(!eligible(&template));
    template.items.pop();
    template.class = Atom::String(b"#32770".to_vec());
    assert!(!eligible(&template));
}
#[test]
fn dialog_icon_eligibility_rejects_partial_creation_and_ambiguous_title_payloads() {
    let original = template();
    for mutation in 0..6 {
        let mut template = original.clone();
        match mutation {
            0 => template.style |= 0x10,
            1 => template.items[0].title = Atom::Ordinal(7),
            2 => template.items[0].creation_data.push(0),
            3 => template.items[0].style = 0x4000_0000,
            4 => template.items[0].style = 0x4000_0013,
            _ => template.items[0].class = Atom::Ordinal(0x80),
        }
        assert!(!eligible(&template));
    }
}
#[test]
fn dialog_icon_eligibility_does_not_restrict_templates_without_icon_sidecars() {
    let mut template = template();
    template.items[0].initial_icon = None;
    template.items[0].creation_data.push(42);
    template.class = Atom::String(b"guest dialog".to_vec());
    template.style |= 0x10;
    assert!(eligible(&template));
}
