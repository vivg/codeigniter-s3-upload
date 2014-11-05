#codeigniter-s3-upload

A Codeigniter Upload Library Extension to upload files directly to S3.

Requires: https://github.com/tpyo/amazon-s3-php-class

## Usage

Use the following functions to upload the file directly to S3 (userfile is default fieldname):

```php
$field_name = "some_field_name";
$this->upload->do_upload_s3($field_name);
```

To get the data of the uploaded file, use the following:

```php
$this->upload->data_s3();
```

