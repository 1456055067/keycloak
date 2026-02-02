//! LDAP search operations.
//!
//! Provides search functionality for users and groups in LDAP directories.

use std::collections::HashMap;

use ldap3::SearchEntry;

use crate::config::LdapConfig;
use crate::connection::LdapConnection;
use crate::error::{LdapError, LdapResult};

/// Represents an LDAP entry with parsed attributes.
#[derive(Debug, Clone)]
pub struct LdapEntry {
    /// Distinguished Name.
    pub dn: String,

    /// Attributes (all values are multi-valued).
    pub attributes: HashMap<String, Vec<String>>,

    /// Binary attributes.
    pub binary_attributes: HashMap<String, Vec<Vec<u8>>>,
}

impl LdapEntry {
    /// Creates a new LDAP entry from search result.
    #[must_use]
    pub fn from_search_entry(entry: SearchEntry) -> Self {
        Self {
            dn: entry.dn,
            attributes: entry.attrs,
            binary_attributes: entry.bin_attrs,
        }
    }

    /// Gets a single-valued attribute.
    #[must_use]
    pub fn get_attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Gets a multi-valued attribute.
    #[must_use]
    pub fn get_attrs(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }

    /// Gets a binary attribute.
    #[must_use]
    pub fn get_binary_attr(&self, name: &str) -> Option<&Vec<u8>> {
        self.binary_attributes
            .get(name)
            .and_then(|v| v.first())
    }

    /// Checks if the entry has an attribute.
    #[must_use]
    pub fn has_attr(&self, name: &str) -> bool {
        self.attributes.contains_key(name)
    }

    /// Gets the external ID (UUID attribute value).
    #[must_use]
    pub fn external_id(&self, uuid_attr: &str) -> Option<String> {
        // Try text first
        if let Some(val) = self.get_attr(uuid_attr) {
            return Some(val.to_string());
        }

        // Try binary (for Active Directory objectGUID)
        if let Some(bytes) = self.get_binary_attr(uuid_attr) {
            return Some(format_guid(bytes));
        }

        None
    }
}

/// Formats a binary GUID (Active Directory format) as a string.
fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return hex::encode(bytes);
    }

    // Active Directory GUID format (mixed endianness)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// LDAP search helper.
pub struct LdapSearcher<'a> {
    conn: &'a mut LdapConnection,
    config: &'a LdapConfig,
}

impl<'a> LdapSearcher<'a> {
    /// Creates a new searcher.
    pub fn new(conn: &'a mut LdapConnection, config: &'a LdapConfig) -> Self {
        Self { conn, config }
    }

    /// Searches for users matching a filter.
    pub async fn search_users(
        &mut self,
        filter: &str,
        first: usize,
        max: usize,
    ) -> LdapResult<Vec<LdapEntry>> {
        let attrs = vec![
            "dn",
            self.config.username_attribute.as_str(),
            self.config.uuid_attribute.as_str(),
            self.config.email_attribute.as_str(),
            self.config.first_name_attribute.as_str(),
            self.config.last_name_attribute.as_str(),
            "cn",
            "memberOf",
        ];
        let users_dn = self.config.users_dn.clone();
        let scope = self.config.search_scope.to_ldap3();
        let max_results = self.config.max_results;

        let (rs, _result) = self
            .conn
            .ldap_mut()
            .search(&users_dn, scope, filter, attrs)
            .await
            .map_err(|e| LdapError::Search(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Search(format!("Search failed: {e:?}")))?;

        let entries: Vec<LdapEntry> = rs
            .into_iter()
            .map(SearchEntry::construct)
            .map(LdapEntry::from_search_entry)
            .skip(first)
            .take(max.min(max_results))
            .collect();

        Ok(entries)
    }

    /// Finds a user by username.
    pub async fn find_user_by_username(
        &mut self,
        username: &str,
    ) -> LdapResult<Option<LdapEntry>> {
        let filter = self.config.user_by_username_filter(username);
        let entries = self.search_users(&filter, 0, 1).await?;
        Ok(entries.into_iter().next())
    }

    /// Finds a user by email.
    pub async fn find_user_by_email(&mut self, email: &str) -> LdapResult<Option<LdapEntry>> {
        let filter = self.config.user_by_email_filter(email);
        let entries = self.search_users(&filter, 0, 1).await?;
        Ok(entries.into_iter().next())
    }

    /// Finds a user by external ID (UUID).
    pub async fn find_user_by_external_id(
        &mut self,
        external_id: &str,
    ) -> LdapResult<Option<LdapEntry>> {
        let uuid_attr = &self.config.uuid_attribute;
        let filter = format!(
            "(&{}({}={}))",
            self.config.user_search_filter(),
            uuid_attr,
            external_id
        );
        let entries = self.search_users(&filter, 0, 1).await?;
        Ok(entries.into_iter().next())
    }

    /// Counts users matching a filter.
    pub async fn count_users(&mut self, filter: Option<&str>) -> LdapResult<usize> {
        let base_filter = self.config.user_search_filter();
        let search_filter = match filter {
            Some(f) => format!("(&{base_filter}{f})"),
            None => base_filter,
        };
        let users_dn = self.config.users_dn.clone();
        let scope = self.config.search_scope.to_ldap3();

        let (rs, _result) = self
            .conn
            .ldap_mut()
            .search(&users_dn, scope, &search_filter, vec!["dn"])
            .await
            .map_err(|e| LdapError::Search(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Search(format!("Count failed: {e:?}")))?;

        Ok(rs.len())
    }

    /// Gets the user DN from username.
    pub async fn get_user_dn(&mut self, username: &str) -> LdapResult<Option<String>> {
        let entry = self.find_user_by_username(username).await?;
        Ok(entry.map(|e| e.dn))
    }
}

/// Searches for groups.
pub struct LdapGroupSearcher<'a> {
    conn: &'a mut LdapConnection,
    config: &'a LdapConfig,
}

impl<'a> LdapGroupSearcher<'a> {
    /// Creates a new group searcher.
    pub fn new(conn: &'a mut LdapConnection, config: &'a LdapConfig) -> Self {
        Self { conn, config }
    }

    /// Gets groups for a user DN.
    pub async fn get_user_groups(&mut self, user_dn: &str) -> LdapResult<Vec<String>> {
        let groups_dn = match &self.config.groups_dn {
            Some(dn) => dn.clone(),
            None => return Ok(vec![]),
        };

        let filter = format!("(member={})", user_dn);
        let group_class = self.config.group_object_classes[0].clone();
        let full_filter = format!("(&(objectClass={group_class}){filter})");

        let (rs, _result) = self
            .conn
            .ldap_mut()
            .search(&groups_dn, ldap3::Scope::Subtree, &full_filter, vec!["dn", "cn"])
            .await
            .map_err(|e| LdapError::Search(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Search(format!("Group search failed: {e:?}")))?;

        let groups: Vec<String> = rs
            .into_iter()
            .filter_map(|r| {
                let entry = SearchEntry::construct(r);
                entry.attrs.get("cn").and_then(|v| v.first()).cloned()
            })
            .collect();

        Ok(groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_entry_get_attr() {
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["John Doe".to_string()]);
        attrs.insert(
            "mail".to_string(),
            vec!["john@example.com".to_string()],
        );

        let entry = LdapEntry {
            dn: "cn=john,ou=users,dc=example,dc=com".to_string(),
            attributes: attrs,
            binary_attributes: HashMap::new(),
        };

        assert_eq!(entry.get_attr("cn"), Some("John Doe"));
        assert_eq!(entry.get_attr("mail"), Some("john@example.com"));
        assert_eq!(entry.get_attr("missing"), None);
        assert!(entry.has_attr("cn"));
        assert!(!entry.has_attr("missing"));
    }

    #[test]
    fn format_guid_works() {
        // Example Active Directory objectGUID
        let guid_bytes: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04, // Data1 (little-endian)
            0x05, 0x06, // Data2 (little-endian)
            0x07, 0x08, // Data3 (little-endian)
            0x09, 0x0A, // Data4[0..2]
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // Data4[2..8]
        ];

        let formatted = format_guid(&guid_bytes);
        assert_eq!(formatted, "04030201-0605-0807-090a-0b0c0d0e0f10");
    }
}
