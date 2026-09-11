// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Owned wrappers over the Windows Installer database handles.
//!
//! Every `MSIHANDLE` this module hands out is closed exactly once on drop.
//! Values cross the boundary as UTF-16 with an explicit NUL; the raw handle
//! and the wide buffers never escape.

use core::fmt;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSIDBSTATE, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiDatabaseCommit,
    MsiDatabaseOpenViewW, MsiGetSummaryInformationW, MsiOpenDatabaseW, MsiRecordSetInteger,
    MsiRecordSetStreamW, MsiRecordSetStringW, MsiSummaryInfoPersist, MsiSummaryInfoSetPropertyW,
    MsiViewExecute,
};

/// Windows Installer opened the database for direct creation.
///
/// The persist argument is a sentinel pointer value rather than a string,
/// which is why it is cast from an integer instead of being spelled as text.
const MSIDBOPEN_CREATEDIRECT: MSIDBSTATE = 4;

/// `ERROR_SUCCESS`.
const SUCCESS: u32 = 0;

/// A Windows Installer call reported a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiError {
    /// Which call failed.
    operation: &'static str,
    /// The Windows error code the call returned.
    code: u32,
    /// Detail identifying the row or property involved, when known.
    detail: Option<String>,
}

impl MsiError {
    const fn new(operation: &'static str, code: u32) -> Self {
        Self {
            operation,
            code,
            detail: None,
        }
    }

    fn with_detail(operation: &'static str, code: u32, detail: impl Into<String>) -> Self {
        Self {
            operation,
            code,
            detail: Some(detail.into()),
        }
    }

    /// The Windows error code the failing call returned.
    #[must_use]
    pub const fn code(&self) -> u32 {
        self.code
    }
}

impl fmt::Display for MsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{} failed ({}) for {detail}", self.operation, self.code),
            None => write!(f, "{} failed ({})", self.operation, self.code),
        }
    }
}

impl std::error::Error for MsiError {}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

fn wide_path(value: &Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

/// An owned `MSIHANDLE` closed on drop.
#[derive(Debug)]
struct Handle(MSIHANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // Closing is best effort: there is no recovery from a failed close
        // and returning an error from drop is not possible.
        unsafe {
            let _ = MsiCloseHandle(self.0);
        }
    }
}

/// A record used to bind parameters to a parameterised query.
///
/// Binding through a record keeps values out of the SQL text, so nothing
/// in a package definition can be misread as syntax.
#[derive(Debug)]
pub struct Record(Handle);

impl Record {
    /// Creates a record with `fields` bindable parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if Windows Installer cannot allocate the record.
    pub fn new(fields: u32) -> Result<Self, MsiError> {
        let handle = unsafe { MsiCreateRecord(fields) };
        if handle == 0 {
            return Err(MsiError::new("MsiCreateRecord", 0));
        }
        Ok(Self(Handle(handle)))
    }

    /// Binds a text value to a one-based field.
    ///
    /// # Errors
    ///
    /// Returns an error if the field index is out of range.
    pub fn set_string(&mut self, field: u32, value: &str) -> Result<(), MsiError> {
        let text = wide(value);
        let status = unsafe { MsiRecordSetStringW(self.0.0, field, text.as_ptr()) };
        if status == SUCCESS {
            Ok(())
        } else {
            Err(MsiError::with_detail(
                "MsiRecordSetStringW",
                status,
                format!("field {field}"),
            ))
        }
    }

    /// Binds an integer value to a one-based field.
    ///
    /// # Errors
    ///
    /// Returns an error if the field index is out of range.
    pub fn set_integer(&mut self, field: u32, value: i32) -> Result<(), MsiError> {
        let status = unsafe { MsiRecordSetInteger(self.0.0, field, value) };
        if status == SUCCESS {
            Ok(())
        } else {
            Err(MsiError::with_detail(
                "MsiRecordSetInteger",
                status,
                format!("field {field}"),
            ))
        }
    }

    /// Binds the contents of a file as a stream on a one-based field.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read into the database.
    pub fn set_stream(&mut self, field: u32, path: &Path) -> Result<(), MsiError> {
        let text = wide_path(path);
        let status = unsafe { MsiRecordSetStreamW(self.0.0, field, text.as_ptr()) };
        if status == SUCCESS {
            Ok(())
        } else {
            Err(MsiError::with_detail(
                "MsiRecordSetStreamW",
                status,
                path.display().to_string(),
            ))
        }
    }
}

/// A Windows Installer database being authored.
#[derive(Debug)]
pub struct Database {
    handle: Handle,
}

impl Database {
    /// Creates a new installer database at `path`, replacing any existing file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created.
    pub fn create(path: &Path) -> Result<Self, MsiError> {
        if path.exists() {
            std::fs::remove_file(path).map_err(|error| {
                MsiError::with_detail("remove existing package", 0, error.to_string())
            })?;
        }
        let text = wide_path(path);
        let mut handle: MSIHANDLE = 0;
        let status = unsafe {
            MsiOpenDatabaseW(
                text.as_ptr(),
                MSIDBOPEN_CREATEDIRECT as *const u16,
                &raw mut handle,
            )
        };
        if status != SUCCESS {
            return Err(MsiError::with_detail(
                "MsiOpenDatabaseW",
                status,
                path.display().to_string(),
            ));
        }
        Ok(Self {
            handle: Handle(handle),
        })
    }

    /// Runs a statement that binds no parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the statement is rejected or fails to execute.
    pub fn execute(&self, sql: &str) -> Result<(), MsiError> {
        self.run(sql, None)
    }

    /// Runs a statement, binding `record` to its `?` parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the statement is rejected or fails to execute.
    pub fn execute_with(&self, sql: &str, record: &Record) -> Result<(), MsiError> {
        self.run(sql, Some(record))
    }

    fn run(&self, sql: &str, record: Option<&Record>) -> Result<(), MsiError> {
        let text = wide(sql);
        let mut view: MSIHANDLE = 0;
        let status = unsafe { MsiDatabaseOpenViewW(self.handle.0, text.as_ptr(), &raw mut view) };
        if status != SUCCESS {
            return Err(MsiError::with_detail(
                "MsiDatabaseOpenViewW",
                status,
                sql.to_owned(),
            ));
        }
        let view = Handle(view);
        let parameters = record.map_or(0, |record| record.0.0);
        let status = unsafe { MsiViewExecute(view.0, parameters) };
        if status != SUCCESS {
            return Err(MsiError::with_detail(
                "MsiViewExecute",
                status,
                sql.to_owned(),
            ));
        }
        Ok(())
    }

    /// Writes the summary information stream.
    ///
    /// `properties` pairs a summary property identifier with its value. The
    /// stream must be written before the database is committed.
    ///
    /// # Errors
    ///
    /// Returns an error if any property is rejected or the stream cannot be
    /// persisted.
    pub fn write_summary_information(
        &self,
        properties: &[(u32, SummaryValue<'_>)],
    ) -> Result<(), MsiError> {
        let mut summary: MSIHANDLE = 0;
        let count = u32::try_from(properties.len()).unwrap_or(u32::MAX);
        // With a database handle the path argument must be null; supplying
        // both is rejected.
        let status = unsafe {
            MsiGetSummaryInformationW(self.handle.0, core::ptr::null(), count, &raw mut summary)
        };
        if status != SUCCESS {
            return Err(MsiError::new("MsiGetSummaryInformationW", status));
        }
        let summary = Handle(summary);

        for (property, value) in properties {
            let (data_type, integer, text) = match value {
                SummaryValue::Integer(value) => (VT_I4, *value, Vec::new()),
                SummaryValue::Text(value) => (VT_LPSTR, 0, wide(value)),
            };
            let pointer = if text.is_empty() {
                core::ptr::null()
            } else {
                text.as_ptr()
            };
            let status = unsafe {
                MsiSummaryInfoSetPropertyW(
                    summary.0,
                    *property,
                    data_type,
                    integer,
                    core::ptr::null_mut::<FILETIME>(),
                    pointer,
                )
            };
            if status != SUCCESS {
                return Err(MsiError::with_detail(
                    "MsiSummaryInfoSetPropertyW",
                    status,
                    format!("property {property}"),
                ));
            }
        }

        let status = unsafe { MsiSummaryInfoPersist(summary.0) };
        if status != SUCCESS {
            return Err(MsiError::new("MsiSummaryInfoPersist", status));
        }
        Ok(())
    }

    /// Commits every pending change to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be committed.
    pub fn commit(self) -> Result<(), MsiError> {
        let status = unsafe { MsiDatabaseCommit(self.handle.0) };
        if status == SUCCESS {
            Ok(())
        } else {
            Err(MsiError::new("MsiDatabaseCommit", status))
        }
    }
}

/// `VT_I4`, a 32-bit signed summary property.
const VT_I4: u32 = 3;
/// `VT_LPSTR`, a text summary property.
const VT_LPSTR: u32 = 30;

/// A value written into the summary information stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryValue<'a> {
    /// A 32-bit signed integer property.
    Integer(i32),
    /// A text property.
    Text(&'a str),
}
