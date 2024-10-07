use derive_new::new;

use super::template::Template;

#[derive(new)]
pub(crate) struct ObjectSearch {
    template: Template,
}

impl ObjectSearch {
    pub(crate) fn get_template(&self) -> &Template {
        &self.template
    }
}
